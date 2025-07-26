using AuthServer.Authentication.Abstractions;
using AuthServer.Authorization;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Cache.Abstractions;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Options;
using AuthServer.Repositories.Abstractions;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.Extensions.Options;

namespace AuthServer.PushedAuthorization;
internal class PushedAuthorizationRequestValidator : BaseAuthorizeValidator, IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>
{
    private readonly ICachedClientStore _cachedClientStore;
    private readonly IClientAuthenticationService _clientAuthenticationService;
    private readonly ISecureRequestService _secureRequestService;
    private readonly IDPoPService _dPoPService;

    public PushedAuthorizationRequestValidator(
        ICachedClientStore cachedClientStore,
        IClientAuthenticationService clientAuthenticationService,
        INonceRepository nonceRepository,
        ITokenDecoder<ServerIssuedTokenDecodeArguments> tokenDecoder,
        IOptionsSnapshot<DiscoveryDocument> discoveryDocumentOptions,
        ISecureRequestService secureRequestService,
        IAuthorizationGrantRepository authorizationGrantRepository,
        IClientRepository clientRepository,
        IDPoPService dPoPService)
        : base(nonceRepository, tokenDecoder, discoveryDocumentOptions, authorizationGrantRepository, clientRepository)
    {
        _cachedClientStore = cachedClientStore;
        _clientAuthenticationService = clientAuthenticationService;
        _secureRequestService = secureRequestService;
        _dPoPService = dPoPService;
    }

    public async Task<ProcessResult<PushedAuthorizationValidatedRequest, ProcessError>> Validate(PushedAuthorizationRequest request, CancellationToken cancellationToken)
    {
        var isClientAuthenticationMethodInvalid = request.ClientAuthentications.Count != 1;
        if (isClientAuthenticationMethodInvalid)
        {
            return PushedAuthorizationError.MultipleOrNoneClientMethod;
        }

        var clientAuthentication = request.ClientAuthentications.Single();
        var clientAuthenticationResult = await _clientAuthenticationService.AuthenticateClient(clientAuthentication, cancellationToken);
        if (!clientAuthenticationResult.IsAuthenticated || string.IsNullOrWhiteSpace(clientAuthenticationResult.ClientId))
        {
            return PushedAuthorizationError.InvalidClient;
        }

        var cachedClient = await _cachedClientStore.Get(clientAuthenticationResult.ClientId, cancellationToken);
        if (!HasValidEmptyRequest(request.RequestObject, null, cachedClient.RequireSignedRequestObject))
        {
            return PushedAuthorizationError.RequestRequiredAsRequestObject;
        }

        var isRequestObjectEmpty = string.IsNullOrEmpty(request.RequestObject);
        if (!isRequestObjectEmpty)
        {
            var newRequest = await _secureRequestService.GetRequestByObject(request.RequestObject!, clientAuthenticationResult.ClientId, ClientTokenAudience.PushedAuthorizationEndpoint, cancellationToken);
            if (newRequest is null)
            {
                return PushedAuthorizationError.InvalidRequest;
            }

            request = new PushedAuthorizationRequest(newRequest, request.ClientAuthentications, request.DPoP);
        }

        if (!HasValidState(request.State))
        {
            return PushedAuthorizationError.InvalidState;
        }

        if (!HasValidEmptyRedirectUri(request.RedirectUri, cachedClient))
        {
            return PushedAuthorizationError.InvalidRedirectUri;
        }

        if (!HasValidRedirectUri(request.RedirectUri, cachedClient))
        {
            return PushedAuthorizationError.UnauthorizedRedirectUri;
        }

        if (!HasValidResponseMode(request.ResponseMode))
        {
            return PushedAuthorizationError.InvalidResponseMode;
        }

        if (!HasValidResponseType(request.ResponseType))
        {
            return PushedAuthorizationError.InvalidResponseType;
        }

        if (!HasAuthorizationCodeGrantType(cachedClient))
        {
            return PushedAuthorizationError.UnauthorizedResponseType;
        }

        if (!HasValidDisplay(request.Display))
        {
            return PushedAuthorizationError.InvalidDisplay;
        }

        if (!HasValidNonce(request.Nonce))
        {
            return PushedAuthorizationError.InvalidNonce;
        }

        if (!await HasUniqueNonce(request.Nonce!, cancellationToken))
        {
            return PushedAuthorizationError.ReplayNonce;
        }

        if (!HasValidCodeChallengeMethod(request.CodeChallengeMethod))
        {
            return PushedAuthorizationError.InvalidCodeChallengeMethod;
        }

        if (!HasValidCodeChallenge(request.CodeChallenge))
        {
            return PushedAuthorizationError.InvalidCodeChallenge;
        }

        if (!HasValidScope(request.Scope))
        {
            return PushedAuthorizationError.InvalidOpenIdScope;
        }

        if (!HasAuthorizedScope(request.Scope, cachedClient))
        {
            return PushedAuthorizationError.UnauthorizedScope;
        }

        if (!await HasValidResource(request.Resource, request.Scope, cancellationToken))
        {
            return PushedAuthorizationError.InvalidResource;
        }

        if (!HasValidMaxAge(request.MaxAge))
        {
            return PushedAuthorizationError.InvalidMaxAge;
        }

        if (!await HasValidIdTokenHint(request.IdTokenHint, clientAuthenticationResult.ClientId, cancellationToken))
        {
            return PushedAuthorizationError.InvalidIdTokenHint;
        }

        if (!HasValidPrompt(request.Prompt))
        {
            return PushedAuthorizationError.InvalidPrompt;
        }

        if (!HasValidAcrValues(request.AcrValues))
        {
            return PushedAuthorizationError.InvalidAcrValues;
        }
        
        if (!HasValidGrantManagementAction(request.GrantId, request.GrantManagementAction))
        {
            return PushedAuthorizationError.InvalidGrantManagement;
        }

        if (!await HasValidGrantId(request.GrantId, cachedClient.Id, cancellationToken))
        {
            return PushedAuthorizationError.InvalidGrantId;
        }

        if (!HasValidDPoP(request.DPoPJkt, request.DPoP, cachedClient.RequireDPoPBoundAccessTokens))
        {
            return PushedAuthorizationError.DPoPRequired;
        }

        var dPoPValidationResult = new DPoPValidationResult();
        if (!string.IsNullOrEmpty(request.DPoP))
        {
            dPoPValidationResult = await _dPoPService.ValidateDPoP(request.DPoP, cachedClient.Id, cancellationToken);
            if (dPoPValidationResult is { IsValid: false, RenewDPoPNonce: false })
            {
                return PushedAuthorizationError.InvalidDPoP;
            }

            if (dPoPValidationResult is { IsValid: false, RenewDPoPNonce: true })
            {
                return PushedAuthorizationError.RenewDPoPNonce(clientAuthenticationResult.ClientId);
            }

            var isJktValid = string.IsNullOrEmpty(request.DPoPJkt) || request.DPoPJkt == dPoPValidationResult.DPoPJkt;
            if (!isJktValid)
            {
                return PushedAuthorizationError.InvalidDPoPJktMatch;
            }
        }

        return new PushedAuthorizationValidatedRequest
        {
            LoginHint = request.LoginHint,
            IdTokenHint = request.IdTokenHint,
            Prompt = request.Prompt,
            Display = request.Display,
            ResponseType = request.ResponseType!,
            ResponseMode = request.ResponseMode,
            CodeChallenge = request.CodeChallenge!,
            CodeChallengeMethod = request.CodeChallengeMethod!,
            Scope = request.Scope,
            AcrValues = request.AcrValues,
            Resource = request.Resource,
            ClientId = clientAuthenticationResult.ClientId,
            MaxAge = request.MaxAge,
            Nonce = request.Nonce!,
            State = request.State!,
            RedirectUri = request.RedirectUri,
            GrantId = request.GrantId,
            GrantManagementAction = request.GrantManagementAction,
            DPoPJkt = dPoPValidationResult.DPoPJkt ?? request.DPoPJkt
        };
    }
}