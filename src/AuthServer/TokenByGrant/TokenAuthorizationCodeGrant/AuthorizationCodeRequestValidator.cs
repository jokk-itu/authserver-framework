using AuthServer.Authentication.Abstractions;
using AuthServer.Authorization.Abstractions;
using AuthServer.Cache.Abstractions;
using AuthServer.Codes;
using AuthServer.Codes.Abstractions;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Helpers;
using AuthServer.Repositories.Abstractions;

namespace AuthServer.TokenByGrant.TokenAuthorizationCodeGrant;

internal class AuthorizationCodeRequestValidator : BaseTokenValidator, IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>
{
    private readonly ICodeEncoder<EncodedAuthorizationCode> _authorizationCodeEncoder;
    private readonly ICachedClientStore _cachedEntityStore;
    private readonly IAuthorizationCodeRepository _authorizationCodeRepository;

    public AuthorizationCodeRequestValidator(
        ICodeEncoder<EncodedAuthorizationCode> authorizationCodeEncoder,
        IClientAuthenticationService clientAuthenticationService,
        ICachedClientStore cachedEntityStore,
        IAuthorizationCodeRepository authorizationCodeRepository,
        IDPoPService dPoPService,
        IScopeResourceService scopeResourceService)
        : base(dPoPService, clientAuthenticationService, scopeResourceService)
    {
        _authorizationCodeEncoder = authorizationCodeEncoder;
        _cachedEntityStore = cachedEntityStore;
        _authorizationCodeRepository = authorizationCodeRepository;
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

        var isActiveCode = await _authorizationCodeRepository.IsActiveAuthorizationCode(authorizationCode.AuthorizationCodeId, cancellationToken);
        if (!isActiveCode)
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

        return new AuthorizationCodeValidatedRequest
        {
            ClientId = clientId,
            AuthorizationGrantId = authorizationCode.AuthorizationGrantId,
            AuthorizationCodeId = authorizationCode.AuthorizationCodeId,
            DPoPJkt = authorizationCode.DPoPJkt,
            Resource = authorizationCode.Resource,
            Scope = authorizationCode.Scope
        };
    }
}