using AuthServer.Authentication.Abstractions;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Cache.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Entities;
using AuthServer.Extensions;
using AuthServer.Helpers;
using AuthServer.Repositories.Abstractions;
using AuthServer.Repositories.Models;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.TokenByGrant.RefreshTokenGrant;

internal class RefreshTokenRequestValidator : IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>
{
    private readonly AuthorizationDbContext _identityContext;
    private readonly ITokenDecoder<ServerIssuedTokenDecodeArguments> _tokenDecoder;
    private readonly IClientAuthenticationService _clientAuthenticationService;
    private readonly ICachedClientStore _cachedClientStore;
    private readonly IClientRepository _clientRepository;
    private readonly IConsentRepository _consentGrantRepository;
    private readonly IDPoPService _dPoPService;

    public RefreshTokenRequestValidator(
        AuthorizationDbContext identityContext,
        ITokenDecoder<ServerIssuedTokenDecodeArguments> tokenDecoder,
        IClientAuthenticationService clientAuthenticationService,
        ICachedClientStore cachedClientStore,
        IClientRepository clientRepository,
        IConsentRepository consentGrantRepository,
        IDPoPService dPoPService)
    {
        _identityContext = identityContext;
        _tokenDecoder = tokenDecoder;
        _clientAuthenticationService = clientAuthenticationService;
        _cachedClientStore = cachedClientStore;
        _clientRepository = clientRepository;
        _consentGrantRepository = consentGrantRepository;
        _dPoPService = dPoPService;
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

        if (request.ClientAuthentications.Count != 1)
        {
            return TokenError.MultipleOrNoneClientMethod;
        }

        var clientAuthentication = request.ClientAuthentications.Single();
        var clientAuthenticationResult = await _clientAuthenticationService.AuthenticateClient(clientAuthentication, cancellationToken);
        if (!clientAuthenticationResult.IsAuthenticated || string.IsNullOrWhiteSpace(clientAuthenticationResult.ClientId))
        {
            return TokenError.InvalidClient;
        }
        
        var clientId = clientAuthenticationResult.ClientId!;
        string? authorizationGrantId;
        if (TokenHelper.IsJsonWebToken(request.RefreshToken))
        {
            authorizationGrantId = await ValidateStructuredToken(clientId, request.RefreshToken, cancellationToken);
        }
        else
        {
            authorizationGrantId = await ValidateReferenceToken(request.RefreshToken, cancellationToken);
        }

        if (authorizationGrantId is null)
        {
            return TokenError.InvalidRefreshToken;
        }

        var cachedClient = await _cachedClientStore.Get(clientId, cancellationToken);

        if (cachedClient.GrantTypes.All(x => x != GrantTypeConstants.RefreshToken))
        {
            return TokenError.UnauthorizedForGrantType;
        }

        if (cachedClient.RequireDPoPBoundAccessTokens && string.IsNullOrEmpty(request.DPoP))
        {
            return TokenError.DPoPRequired;
        }

        var dPoPValidationResult = new DPoPValidationResult
        {
            IsValid = false
        };
        if (!string.IsNullOrEmpty(request.DPoP))
        {
            dPoPValidationResult = await _dPoPService.ValidateDPoP(request.DPoP, clientId, cancellationToken);
            if (dPoPValidationResult is { IsValid: false, DPoPNonce: null })
            {
                return TokenError.InvalidDPoP;
            }

            if (dPoPValidationResult is { IsValid: false })
            {
                return TokenError.UseDPoPNonce(dPoPValidationResult.DPoPNonce!);
            }
        }

        IReadOnlyCollection<string> requestedScopes;
        var isScopeRequested = request.Scope.Count != 0;

        if (cachedClient.RequireConsent)
        {
            var grantConsentScopes = await _consentGrantRepository.GetGrantConsentedScopes(authorizationGrantId, cancellationToken);
            if (grantConsentScopes.Count == 0)
            {
                return TokenError.ConsentRequired;
            }

            requestedScopes = isScopeRequested ? request.Scope : grantConsentScopes.Select(x => x.Name).ToList();
            if (requestedScopes.SelectMany(_ => request.Resource, (x, y) => new ScopeDto(x, y)).IsNotSubset(grantConsentScopes))
            {
                return TokenError.ScopeExceedsConsentedScope;
            }
        }
        else
        {
            requestedScopes = isScopeRequested ? request.Scope : cachedClient.Scopes;
            if (requestedScopes.IsNotSubset(cachedClient.Scopes))
            {
                return TokenError.UnauthorizedForScope;
            }

            var doesResourceExist = await _clientRepository.DoesResourcesExist(request.Resource, requestedScopes, cancellationToken);
            if (!doesResourceExist)
            {
                return TokenError.InvalidResource;
            }
        }

        return new RefreshTokenValidatedRequest
        {
            AuthorizationGrantId = authorizationGrantId,
            ClientId = clientId,
            DPoPJkt = dPoPValidationResult.DPoPJkt,
            Resource = request.Resource,
            Scope = requestedScopes
        };
    }

    private async Task<string?> ValidateReferenceToken(string refreshToken, CancellationToken cancellationToken)
    {
        var authorizationGrantId = await _identityContext
            .Set<RefreshToken>()
            .Where(x => x.Reference == refreshToken)
            .Where(Token.IsActive)
            .OfType<RefreshToken>()
            .Select(x => x.AuthorizationGrant.Id)
            .SingleOrDefaultAsync(cancellationToken: cancellationToken);

        return authorizationGrantId;
    }

    private async Task<string?> ValidateStructuredToken(string clientId, string refreshToken, CancellationToken cancellationToken)
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
        var jti = Guid.Parse(validatedToken.Claims.Single(x => x.Type == ClaimNameConstants.Jti).Value);

        var isActive = await _identityContext
            .Set<RefreshToken>()
            .Where(x => x.Id == jti)
            .Where(Token.IsActive)
            .AnyAsync(cancellationToken: cancellationToken);

        return isActive ? authorizationGrantId : null;
    }
}