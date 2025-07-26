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
    private readonly ITokenDecoder<ServerIssuedTokenDecodeArguments> _tokenDecoder;
    private readonly ICachedClientStore _cachedClientStore;

    public RefreshTokenRequestValidator(
        AuthorizationDbContext identityContext,
        ITokenDecoder<ServerIssuedTokenDecodeArguments> tokenDecoder,
        IClientAuthenticationService clientAuthenticationService,
        ICachedClientStore cachedClientStore,
        IClientRepository clientRepository,
        IConsentRepository consentRepository,
        IDPoPService dPoPService)
        : base(dPoPService, clientAuthenticationService, consentRepository, clientRepository)
    {
        _identityContext = identityContext;
        _tokenDecoder = tokenDecoder;
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
        RefreshTokenValidationResult? refreshTokenValidationResult;
        if (TokenHelper.IsJsonWebToken(request.RefreshToken))
        {
            refreshTokenValidationResult = await ValidateStructuredToken(clientId, request.RefreshToken, cancellationToken);
        }
        else
        {
            refreshTokenValidationResult = await ValidateReferenceToken(request.RefreshToken, cancellationToken);
        }

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

    private async Task<RefreshTokenValidationResult?> ValidateReferenceToken(string refreshToken, CancellationToken cancellationToken)
    {
        var refreshTokenValidationResult = await _identityContext
            .Set<RefreshToken>()
            .Where(x => x.Reference == refreshToken)
            .Where(Token.IsActive)
            .OfType<RefreshToken>()
            .Select(x => new RefreshTokenValidationResult(x.AuthorizationGrant.Id, x.Jkt))
            .SingleOrDefaultAsync(cancellationToken: cancellationToken);

        return refreshTokenValidationResult;
    }

    private async Task<RefreshTokenValidationResult?> ValidateStructuredToken(string clientId, string refreshToken, CancellationToken cancellationToken)
    {
        var validatedToken = await _tokenDecoder.Validate(refreshToken, new ServerIssuedTokenDecodeArguments
        {
            ValidateLifetime = true,
            Audiences = [clientId],
            TokenTypes = [TokenTypeHeaderConstants.RefreshToken]
        }, cancellationToken);

        if (validatedToken is null)
        {
            return null;
        }

        var authorizationGrantId = validatedToken.Claims.Single(x => x.Type == ClaimNameConstants.GrantId).Value;
        var jkt = validatedToken.Claims.SingleOrDefault(x => x.Type == ClaimNameConstants.Jkt)?.Value;
        var jti = Guid.Parse(validatedToken.Claims.Single(x => x.Type == ClaimNameConstants.Jti).Value);

        var isActive = await _identityContext
            .Set<RefreshToken>()
            .Where(x => x.Id == jti)
            .Where(Token.IsActive)
            .AnyAsync(cancellationToken: cancellationToken);

        return isActive ? new RefreshTokenValidationResult(authorizationGrantId, jkt) : null;
    }

    private sealed record RefreshTokenValidationResult(string AuthorizationGrantId, string? Jkt);
}