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
using AuthServer.Helpers;
using AuthServer.Repositories.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.TokenByGrant.TokenAuthorizationCodeGrant;

internal class AuthorizationCodeRequestValidator : BaseTokenValidator, IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>
{
    private readonly AuthorizationDbContext _identityContext;
    private readonly ICodeEncoder<EncodedAuthorizationCode> _authorizationCodeEncoder;
    private readonly ICachedClientStore _cachedEntityStore;

    public AuthorizationCodeRequestValidator(
        AuthorizationDbContext identityContext,
        ICodeEncoder<EncodedAuthorizationCode> authorizationCodeEncoder,
        IClientAuthenticationService clientAuthenticationService,
        IClientRepository clientRepository,
        ICachedClientStore cachedEntityStore,
        IConsentRepository consentRepository,
        IDPoPService dPoPService)
        : base(dPoPService, clientAuthenticationService, consentRepository, clientRepository)
    {
        _identityContext = identityContext;
        _authorizationCodeEncoder = authorizationCodeEncoder;
        _cachedEntityStore = cachedEntityStore;
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

        var clientAuthenticationResult = await AuthenticateClient(request.ClientAuthentications, cancellationToken);
        if (!clientAuthenticationResult.IsSuccess)
        {
            return clientAuthenticationResult.Error!;
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

        var clientId = clientAuthenticationResult.Value!;
        var cachedClient = await _cachedEntityStore.Get(clientId, cancellationToken);

        if (cachedClient.GrantTypes.All(x => x != GrantTypeConstants.AuthorizationCode))
        {
            return TokenError.UnauthorizedForGrantType;
        }

        if (!string.IsNullOrWhiteSpace(request.RedirectUri)
            && cachedClient.RedirectUris.All(x => x != request.RedirectUri))
        {
            return TokenError.UnauthorizedForRedirectUri;
        }

        var dPoPResult = await ValidateDPoP(request.DPoP, cachedClient, authorizationCode.DPoPJkt, cancellationToken);
        if (dPoPResult?.Error is not null)
        {
            return dPoPResult.Error;
        }

        var scopeValidationResult = await ValidateScope(authorizationCode.Scope, request.Resource, authorizationCode.AuthorizationGrantId, cachedClient, cancellationToken);
        if (!scopeValidationResult.IsSuccess)
        {
            return scopeValidationResult.Error!;
        }

        return new AuthorizationCodeValidatedRequest
        {
            ClientId = clientId,
            AuthorizationGrantId = authorizationCode.AuthorizationGrantId,
            AuthorizationCodeId = authorizationCode.AuthorizationCodeId,
            DPoPJkt = authorizationCode.DPoPJkt,
            Resource = request.Resource,
            Scope = authorizationCode.Scope
        };
    }
}