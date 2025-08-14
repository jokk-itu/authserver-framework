using AuthServer.Authorization;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorize.Abstractions;
using AuthServer.Cache.Abstractions;
using AuthServer.Cache.Entities;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Options;
using AuthServer.Repositories.Abstractions;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.Extensions.Options;

namespace AuthServer.Authorize;

internal class AuthorizeRequestValidator : BaseAuthorizeValidator, IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>
{
    private readonly ICachedClientStore _cachedClientStore;
    private readonly IAuthorizeInteractionService _authorizeInteractionService;
    private readonly ISecureRequestService _secureRequestService;

    public AuthorizeRequestValidator(
        ICachedClientStore cachedClientStore,
        ITokenDecoder<ServerIssuedTokenDecodeArguments> tokenDecoder,
        IAuthorizeInteractionService authorizeInteractionService,
        ISecureRequestService secureRequestService,
        IOptionsSnapshot<DiscoveryDocument> discoveryDocumentOptions,
        INonceRepository nonceRepository,
        IClientRepository clientRepository,
        IAuthorizationGrantRepository authorizationGrantRepository)
        : base(nonceRepository, tokenDecoder, discoveryDocumentOptions, authorizationGrantRepository, clientRepository)
    {
        _cachedClientStore = cachedClientStore;
        _authorizeInteractionService = authorizeInteractionService;
        _secureRequestService = secureRequestService;
    }

    public async Task<ProcessResult<AuthorizeValidatedRequest, ProcessError>> Validate(AuthorizeRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(request.ClientId))
        {
            return AuthorizeError.InvalidClient;
        }

        var cachedClient = await _cachedClientStore.TryGet(request.ClientId, cancellationToken);
        if (cachedClient == null)
        {
            return AuthorizeError.InvalidClient;
        }

        var isRequestObjectEmpty = string.IsNullOrEmpty(request.RequestObject);
        var isRequestUriEmpty = string.IsNullOrEmpty(request.RequestUri);
        if (!isRequestObjectEmpty && !isRequestUriEmpty)
        {
            return AuthorizeError.InvalidRequestAndRequestUri;
        }

        if (!HasValidEmptyRequest(request.RequestObject, request.RequestUri, cachedClient.RequireSignedRequestObject))
        {
            return AuthorizeError.RequestOrRequestUriRequiredAsRequestObject;
        }

        if (!HasValidRequestUriForPushedAuthorization(request.RequestUri, cachedClient.RequirePushedAuthorizationRequests))
        {
            return AuthorizeError.RequestUriRequiredAsPushedAuthorizationRequest;
        }

        if (request.RequestUri?.StartsWith(RequestUriConstants.RequestUriPrefix) == true)
        {
            return await ValidateFromPushedAuthorization(request, cancellationToken);
        }

        if (!isRequestUriEmpty)
        {
            var substitutedRequestUri = await SubstituteRequestUri(request, cachedClient, cancellationToken);
            if (substitutedRequestUri.IsSuccess)
            {
                request = substitutedRequestUri.Value!;
            }
            else
            {
                return substitutedRequestUri.Error!;
            }
        }
        else if (!isRequestObjectEmpty)
        {
            var substitutedRequestObject = await SubstituteRequestObject(request, cancellationToken);
            if (substitutedRequestObject.IsSuccess)
            {
                request = substitutedRequestObject.Value!;
            }
            else
            {
                return substitutedRequestObject.Error!;
            }
        }

        var parameterError = await ValidateParameters(request, cachedClient, cancellationToken);
        if (parameterError is not null)
        {
            return parameterError;
        }

        return await ValidateForInteraction(request, cancellationToken);
    }

    private static ProcessError? ValidateResponseParameters(AuthorizeRequest request, CachedClient cachedClient)
    {
        if (!HasValidState(request.State))
        {
            return AuthorizeError.InvalidState;
        }

        if (!HasValidEmptyRedirectUri(request.RedirectUri, cachedClient))
        {
            return AuthorizeError.InvalidRedirectUri;
        }

        if (!HasValidRedirectUri(request.RedirectUri, cachedClient))
        {
            return AuthorizeError.UnauthorizedRedirectUri;
        }

        if (!HasValidResponseMode(request.ResponseMode))
        {
            return AuthorizeError.InvalidResponseMode;
        }

        if (!HasValidResponseType(request.ResponseType))
        {
            return AuthorizeError.InvalidResponseType;
        }

        if (!HasAuthorizedResponseType(request.ResponseType!, cachedClient))
        {
            return AuthorizeError.UnauthorizedResponseType;
        }

        return null;
    }

    private async Task<ProcessResult<AuthorizeRequest, ProcessError>> SubstituteRequestObject(AuthorizeRequest request, CancellationToken cancellationToken)
    {
        var newRequest = await _secureRequestService.GetRequestByObject(request.RequestObject!, request.ClientId!, ClientTokenAudience.AuthorizationEndpoint, cancellationToken);
        if (newRequest is null)
        {
            return AuthorizeError.InvalidRequest;
        }

        return new AuthorizeRequest(newRequest);
    }

    private async Task<ProcessResult<AuthorizeRequest, ProcessError>> SubstituteRequestUri(AuthorizeRequest request, CachedClient cachedClient, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(request.RequestUri, UriKind.Absolute, out var requestUri))
        {
            return AuthorizeError.InvalidRequestUri;
        }

        if (!cachedClient.RequestUris.Contains(requestUri.GetLeftPart(UriPartial.Path)))
        {
            return AuthorizeError.UnauthorizedRequestUri;
        }

        var newRequest = await _secureRequestService.GetRequestByReference(requestUri, request.ClientId!, ClientTokenAudience.AuthorizationEndpoint, cancellationToken);
        if (newRequest is null)
        {
            return AuthorizeError.InvalidRequestObjectFromRequestUri;
        }

        return new AuthorizeRequest(newRequest);
    }

    private async Task<ProcessResult<AuthorizeValidatedRequest, ProcessError>> ValidateFromPushedAuthorization(AuthorizeRequest request, CancellationToken cancellationToken)
    {
        var authorizeDto = await _secureRequestService.GetRequestByPushedRequest(request.RequestUri!, request.ClientId!, cancellationToken);
        if (authorizeDto is null)
        {
            return AuthorizeError.InvalidOrExpiredRequestUri;
        }

        request = new AuthorizeRequest(authorizeDto, request.RequestUri);
        return await ValidateForInteraction(request, cancellationToken);
    }

    private async Task<ProcessError?> ValidateParameters(AuthorizeRequest request, CachedClient cachedClient, CancellationToken cancellationToken)
    {
        var responseParametersValidationResult = ValidateResponseParameters(request, cachedClient);
        if (responseParametersValidationResult is not null)
        {
            return responseParametersValidationResult;
        }

        if (!HasValidDisplay(request.Display))
        {
            return AuthorizeError.InvalidDisplay;
        }

        if (!HasValidNonce(request.Nonce, request.ResponseType))
        {
            return AuthorizeError.InvalidNonce;
        }

        if (!await HasUniqueNonce(request.Nonce!, cancellationToken))
        {
            return AuthorizeError.ReplayNonce;
        }

        if (!HasValidCodeChallengeMethod(request.CodeChallengeMethod, request.ResponseType))
        {
            return AuthorizeError.InvalidCodeChallengeMethod;
        }

        if (!HasValidCodeChallenge(request.CodeChallenge, request.ResponseType))
        {
            return AuthorizeError.InvalidCodeChallenge;
        }

        if (!HasValidScope(request.Scope))
        {
            return AuthorizeError.InvalidOpenIdScope;
        }

        if (!HasAuthorizedScope(request.Scope, cachedClient))
        {
            return AuthorizeError.UnauthorizedScope;
        }

        if (!await HasValidResource(request.Resource, request.Scope, cancellationToken))
        {
            return AuthorizeError.InvalidResource;
        }

        if (!HasValidMaxAge(request.MaxAge))
        {
            return AuthorizeError.InvalidMaxAge;
        }

        if (!await HasValidIdTokenHint(request.IdTokenHint, request.ClientId!, cancellationToken))
        {
            return AuthorizeError.InvalidIdTokenHint;
        }

        if (!HasValidPrompt(request.Prompt))
        {
            return AuthorizeError.InvalidPrompt;
        }

        if (!HasValidAcrValues(request.AcrValues))
        {
            return AuthorizeError.InvalidAcrValues;
        }

        if (!HasValidGrantManagementAction(request.GrantId, request.GrantManagementAction))
        {
            return AuthorizeError.InvalidGrantManagement;
        }

        if (!await HasValidGrantId(request.GrantId, cachedClient.Id, cancellationToken))
        {
            return AuthorizeError.InvalidGrantId;
        }

        if (!HasValidDPoP(request.DPoPJkt, null, cachedClient.RequireDPoPBoundAccessTokens, request.ResponseType))
        {
            return AuthorizeError.InvalidDPoPJkt;
        }

        return null;
    }

    // This must first be deduced after successful validation of all input from the request
    private async Task<ProcessResult<AuthorizeValidatedRequest, ProcessError>> ValidateForInteraction(AuthorizeRequest request, CancellationToken cancellationToken)
    {
        var interactionResult = await _authorizeInteractionService.GetInteractionResult(request, cancellationToken);
        if (!interactionResult.IsSuccessful)
        {
            var interactionError = interactionResult.Error!;
            if (!interactionResult.RedirectToInteraction)
            {
                return interactionError;
            }

            var requestUri = request.RequestUri;

            // do not persist the request, if it has already been persisted
            if (requestUri?.StartsWith(RequestUriConstants.RequestUriPrefix) == true)
            {
                return new AuthorizeInteractionError(
                    interactionError.Error,
                    interactionError.ErrorDescription,
                    interactionError.ResultCode,
                    requestUri,
                    request.ClientId!);
            }

            return new PersistRequestUriError(
                interactionError.Error,
                interactionError.ErrorDescription,
                interactionError.ResultCode,
                request);
        }

        return new AuthorizeValidatedRequest
        {
            AuthorizationGrantId = interactionResult.AuthorizationGrantId!,
            GrantManagementAction = request.GrantManagementAction,
            ResponseType = request.ResponseType!,
            ResponseMode = request.ResponseMode,
            CodeChallenge = request.CodeChallenge,
            CodeChallengeMethod = request.CodeChallengeMethod,
            Scope = request.Scope,
            AcrValues = request.AcrValues,
            Resource = request.Resource,
            ClientId = request.ClientId!,
            Nonce = request.Nonce,
            RedirectUri = request.RedirectUri,
            RequestUri = request.RequestUri,
            DPoPJkt = request.DPoPJkt
        };
    }
}