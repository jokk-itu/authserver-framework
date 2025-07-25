using AuthServer.Authentication.Abstractions;
using AuthServer.Authorization.Abstractions;
using AuthServer.Cache.Abstractions;
using AuthServer.Codes;
using AuthServer.Codes.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Entities;
using AuthServer.Extensions;
using AuthServer.Helpers;
using AuthServer.Repositories.Abstractions;
using AuthServer.Repositories.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.TokenByGrant.TokenAuthorizationCodeGrant;

internal class AuthorizationCodeRequestValidator : IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>
{
    private readonly AuthorizationDbContext _identityContext;
    private readonly ICodeEncoder<EncodedAuthorizationCode> _authorizationCodeEncoder;
    private readonly IClientAuthenticationService _clientAuthenticationService;
    private readonly IClientRepository _clientRepository;
    private readonly ICachedClientStore _cachedEntityStore;
    private readonly IConsentRepository _consentGrantRepository;
    private readonly IDPoPService _dPoPService;

    public AuthorizationCodeRequestValidator(
        AuthorizationDbContext identityContext,
        ICodeEncoder<EncodedAuthorizationCode> authorizationCodeEncoder,
        IClientAuthenticationService clientAuthenticationService,
        IClientRepository clientRepository,
        ICachedClientStore cachedEntityStore,
        IConsentRepository consentGrantRepository,
        IDPoPService dPoPService)
    {
        _identityContext = identityContext;
        _authorizationCodeEncoder = authorizationCodeEncoder;
        _clientAuthenticationService = clientAuthenticationService;
        _clientRepository = clientRepository;
        _cachedEntityStore = cachedEntityStore;
        _consentGrantRepository = consentGrantRepository;
        _dPoPService = dPoPService;
    }
    
    public async Task<ProcessResult<AuthorizationCodeValidatedRequest, ProcessError>> Validate(TokenRequest request, CancellationToken cancellationToken)
    {
        if (request.GrantType != GrantTypeConstants.AuthorizationCode)
        {
            return TokenError.UnsupportedGrantType;
        }

        if (request.Resource.Count == 0)
        {
            return TokenError.InvalidResource;
        }

        var authorizationCode = _authorizationCodeEncoder.Decode(request.Code);
        if (authorizationCode is null)
        {
            return TokenError.InvalidCode;
        }

        var isCodeVerifierValid = ProofKeyHelper.IsCodeVerifierValid(request.CodeVerifier, authorizationCode.CodeChallenge, authorizationCode.CodeChallengeMethod);
        if (!isCodeVerifierValid)
        {
            return TokenError.InvalidCodeVerifier;
        }

        var isRedirectUriMismatch = !string.IsNullOrWhiteSpace(authorizationCode.RedirectUri)
                                    && request.RedirectUri != authorizationCode.RedirectUri;

        if (isRedirectUriMismatch)
        {
            return TokenError.InvalidRedirectUri;
        }

        var isClientAuthenticationMethodInvalid = request.ClientAuthentications.Count != 1;
        if (isClientAuthenticationMethodInvalid)
        {
            return TokenError.MultipleOrNoneClientMethod;
        }

        var clientAuthentication = request.ClientAuthentications.Single();
        var clientAuthenticationResult = await _clientAuthenticationService.AuthenticateClient(clientAuthentication, cancellationToken);
        if (!clientAuthenticationResult.IsAuthenticated || string.IsNullOrWhiteSpace(clientAuthenticationResult.ClientId))
        {
            return TokenError.InvalidClient;
        }

        var hasActiveGrant = await _identityContext
            .Set<AuthorizationCodeGrant>()
            .Where(x => x.Id == authorizationCode.AuthorizationGrantId)
            .Where(x => x.AuthorizationCodes
                .AsQueryable()
                .Where(y => y.Id == authorizationCode.AuthorizationCodeId)
                .Any(Code.IsActive))
            .AnyAsync(AuthorizationGrant.IsActive, cancellationToken);

        if (!hasActiveGrant)
        {
            return TokenError.InvalidGrant;
        }

        var clientId = clientAuthenticationResult.ClientId!;
        var cachedClient = await _cachedEntityStore.Get(clientId, cancellationToken);

        if (cachedClient.GrantTypes.All(x => x != request.GrantType))
        {
            return TokenError.UnauthorizedForGrantType;
        }

        if (!string.IsNullOrWhiteSpace(request.RedirectUri)
            && cachedClient.RedirectUris.All(x => x != request.RedirectUri))
        {
            return TokenError.UnauthorizedForRedirectUri;
        }

        var isDPoPRequired = cachedClient.RequireDPoPBoundAccessTokens || authorizationCode.DPoPJkt is not null;
        if (isDPoPRequired && string.IsNullOrEmpty(request.DPoP))
        {
            return TokenError.DPoPRequired;
        }

        if (!string.IsNullOrEmpty(request.DPoP))
        {
            var dPoPValidationResult = await _dPoPService.ValidateDPoP(request.DPoP, clientId, cancellationToken);
            if (dPoPValidationResult is { IsValid: false, DPoPNonce: null, RenewDPoPNonce: false })
            {
                return TokenError.InvalidDPoP;
            }

            if (dPoPValidationResult is { IsValid: false, DPoPNonce: not null })
            {
                return TokenError.UseDPoPNonce(dPoPValidationResult.DPoPNonce!);
            }

            if (dPoPValidationResult is { IsValid: false, RenewDPoPNonce: true })
            {
                return TokenError.RenewDPoPNonce(clientId);
            }

            if (dPoPValidationResult.DPoPJkt != authorizationCode.DPoPJkt)
            {
                return TokenError.InvalidDPoPJktMatch;
            }
        }

        // Request.Scopes cannot be given during authorization_code grant
        var scope = authorizationCode.Scope;

        // Check scope again, as the authorized scope can change
        if (scope.IsNotSubset(cachedClient.Scopes))
        {
            return TokenError.UnauthorizedForScope;
        }

        if (cachedClient.RequireConsent)
        {
            var grantConsentScopes = await _consentGrantRepository.GetGrantConsentedScopes(authorizationCode.AuthorizationGrantId, cancellationToken);
            if (grantConsentScopes.Count == 0)
            {
                return TokenError.ConsentRequired;
            }
            
            if (scope.SelectMany(_ => request.Resource, (x, y) => new ScopeDto(x, y)).IsNotSubset(grantConsentScopes))
            {
                return TokenError.ScopeExceedsConsentedScope;
            }
        }
        else
        {
            var doesResourcesExist = await _clientRepository.DoesResourcesExist(request.Resource, scope, cancellationToken);
            if (!doesResourcesExist)
            {
                return TokenError.InvalidResource;
            }
        }

        return new AuthorizationCodeValidatedRequest
        {
            ClientId = clientId,
            AuthorizationGrantId = authorizationCode.AuthorizationGrantId,
            AuthorizationCodeId = authorizationCode.AuthorizationCodeId,
            DPoPJkt = authorizationCode.DPoPJkt,
            Resource = request.Resource,
            Scope = scope
        };
    }
}