using AuthServer.Authentication.Abstractions;
using AuthServer.Authorization.Abstractions;
using AuthServer.Cache.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Entities;
using AuthServer.Helpers;
using AuthServer.Repositories.Abstractions;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.TokenByGrant.TokenRefreshTokenGrant;

internal class RefreshTokenRequestValidator : BaseTokenValidator, IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>
{
    private readonly AuthorizationDbContext _identityContext;
    private readonly IServerTokenDecoder _serverTokenDecoder;
    private readonly ICachedClientStore _cachedClientStore;

    public RefreshTokenRequestValidator(
        AuthorizationDbContext identityContext,
        IServerTokenDecoder serverTokenDecoder,
        IClientAuthenticationService clientAuthenticationService,
        ICachedClientStore cachedClientStore,
        IClientRepository clientRepository,
        IConsentRepository consentRepository,
        IDPoPService dPoPService)
        : base(dPoPService, clientAuthenticationService, consentRepository, clientRepository)
    {
        _identityContext = identityContext;
        _serverTokenDecoder = serverTokenDecoder;
        _cachedClientStore = cachedClientStore;
    }

    public async Task<ProcessResult<RefreshTokenValidatedRequest, ProcessError>> Validate(TokenRequest request, CancellationToken cancellationToken)
    {
        if (request.GrantType != GrantTypeConstants.RefreshToken)
        {
            return TokenError.UnsupportedGrantType;
        }

        if (string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            return TokenError.InvalidRefreshToken;
        }

        if (request.Resource.Count == 0)
        {
            return TokenError.InvalidResource;
        }

        var clientAuthenticationResult = await AuthenticateClient(request.ClientAuthentications, cancellationToken);
        if (!clientAuthenticationResult.IsSuccess)
        {
            return clientAuthenticationResult.Error!;
        }
        
        var clientId = clientAuthenticationResult.Value!;
        var refreshTokenValidationResult = await ValidateRefreshToken(clientId, request.RefreshToken, cancellationToken);
        if (refreshTokenValidationResult is null)
        {
            return TokenError.InvalidRefreshToken;
        }

        var cachedClient = await _cachedClientStore.Get(clientId, cancellationToken);
        if (cachedClient.GrantTypes.All(x => x != GrantTypeConstants.RefreshToken))
        {
            return TokenError.UnauthorizedForGrantType;
        }

        var dPoPResult = await ValidateDPoP(request.DPoP, cachedClient, refreshTokenValidationResult.Jkt, cancellationToken);
        if (dPoPResult?.Error is not null)
        {
            return dPoPResult.Error;
        }

        var scopeValidationResult = await ValidateScope(request.Scope, request.Resource, refreshTokenValidationResult.AuthorizationGrantId, cachedClient, cancellationToken);
        if (!scopeValidationResult.IsSuccess)
        {
            return scopeValidationResult.Error!;
        }

        return new RefreshTokenValidatedRequest
        {
            AuthorizationGrantId = refreshTokenValidationResult.AuthorizationGrantId,
            ClientId = clientId,
            DPoPJkt = dPoPResult?.DPoPJkt,
            Resource = request.Resource,
            Scope = scopeValidationResult.Value!
        };
    }

    private async Task<RefreshTokenValidationResult?> ValidateRefreshToken(string clientId, string refreshToken, CancellationToken cancellationToken)
    {
        var validatedToken = await _serverTokenDecoder.Validate(refreshToken, new ServerTokenDecodeArguments
        {
            ValidateLifetime = true,
            Audiences = [clientId],
            TokenTypes = [TokenTypeHeaderConstants.RefreshToken]
        }, cancellationToken);

        if (validatedToken is null)
        {
            return null;
        }

        var jti = Guid.Parse(validatedToken.Jti);
        var isActive = await _identityContext
            .Set<RefreshToken>()
            .Where(x => x.Id == jti)
            .Where(Token.IsActive)
            .AnyAsync(cancellationToken: cancellationToken);

        return isActive ? new RefreshTokenValidationResult(validatedToken.GrantId!, validatedToken.Jkt) : null;
    }

    private sealed record RefreshTokenValidationResult(string AuthorizationGrantId, string? Jkt);
}