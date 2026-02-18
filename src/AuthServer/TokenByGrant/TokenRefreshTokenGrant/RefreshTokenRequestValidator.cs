using AuthServer.Authentication.Abstractions;
using AuthServer.Authorization.Abstractions;
using AuthServer.Cache.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;

namespace AuthServer.TokenByGrant.TokenRefreshTokenGrant;

internal class RefreshTokenRequestValidator : BaseTokenValidator, IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>
{
    private readonly IServerTokenDecoder _serverTokenDecoder;
    private readonly ICachedClientStore _cachedClientStore;

    public RefreshTokenRequestValidator(
        IServerTokenDecoder serverTokenDecoder,
        IClientAuthenticationService clientAuthenticationService,
        ICachedClientStore cachedClientStore,
        IClientRepository clientRepository,
        IConsentRepository consentRepository,
        IDPoPService dPoPService)
        : base(dPoPService, clientAuthenticationService, consentRepository, clientRepository)
    {
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

        return validatedToken is not null
            ? new RefreshTokenValidationResult(validatedToken.GrantId!, validatedToken.Jkt)
            : null;
    }

    private sealed record RefreshTokenValidationResult(string AuthorizationGrantId, string? Jkt);
}