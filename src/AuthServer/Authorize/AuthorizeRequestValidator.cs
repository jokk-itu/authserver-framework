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
using AuthServer.RequestAccessors.Authorize;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.Extensions.Options;

namespace AuthServer.Authorize;

internal class AuthorizeRequestValidator : BaseAuthorizeValidator, IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>
{
    private readonly ICachedClientStore _cachedClientStore;
    private readonly IAuthorizeInteractionService _authorizeInteractionService;
    private readonly ISecureRequestService _secureRequestService;
    private readonly IClientRepository _clientRepository;

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
        _clientRepository = clientRepository;
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

        if (isRequestUriEmpty && isRequestObjectEmpty && cachedClient.RequireSignedRequestObject)
        {
            return AuthorizeError.RequestOrRequestUriRequiredAsRequestObject;
        }

        if (isRequestUriEmpty && cachedClient.RequirePushedAuthorizationRequests)
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

    private async Task<ProcessResult<AuthorizeRequest, ProcessError>> SubstituteRequestObject(AuthorizeRequest request, CancellationToken cancellationToken)
    {
        var newRequest = await _secureRequestService.GetRequestByObject(request.RequestObject!, request.ClientId!, ClientTokenAudience.AuthorizeEndpoint, cancellationToken);
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

        var newRequest = await _secureRequestService.GetRequestByReference(requestUri, request.ClientId!, ClientTokenAudience.AuthorizeEndpoint, cancellationToken);
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

        if (!HasValidGrantType(cachedClient))
        {
            return AuthorizeError.UnauthorizedResponseType;
        }

        if (!HasValidDisplay(request.Display))
        {
            return AuthorizeError.InvalidDisplay;
        }

        if (!HasValidNonce(request.Nonce))
        {
            return AuthorizeError.InvalidNonce;
        }

        if (!await HasUniqueNonce(request.Nonce!, cancellationToken))
        {
            return AuthorizeError.ReplayNonce;
        }

        if (!HasValidCodeChallengeMethod(request.CodeChallengeMethod))
        {
            return AuthorizeError.InvalidCodeChallengeMethod;
        }

        if (!HasValidCodeChallenge(request.CodeChallenge))
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
            return AuthorizeError.InvalidTarget;
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
                    request.ClientId!,
                    interactionResult.RedirectToInteraction);
            }

            var authorizeRequestDto = new AuthorizeRequestDto(request);
            var authorizeMessage = await _clientRepository.AddAuthorizeMessage(authorizeRequestDto, cancellationToken);
            requestUri = $"{RequestUriConstants.RequestUriPrefix}{authorizeMessage.Reference}";

            return new AuthorizeInteractionError(
                interactionError.Error,
                interactionError.ErrorDescription,
                interactionError.ResultCode,
                requestUri,
                request.ClientId!,
                interactionResult.RedirectToInteraction);
        }

        return new AuthorizeValidatedRequest
        {
            AuthorizationGrantId = interactionResult.AuthorizationGrantId!,
            GrantManagementAction = request.GrantManagementAction,
            ResponseMode = request.ResponseMode,
            CodeChallenge = request.CodeChallenge!,
            Scope = request.Scope,
            AcrValues = request.AcrValues,
            Resource = request.Resource,
            ClientId = request.ClientId!,
            Nonce = request.Nonce!,
            RedirectUri = request.RedirectUri,
            RequestUri = request.RequestUri
        };
    }
}