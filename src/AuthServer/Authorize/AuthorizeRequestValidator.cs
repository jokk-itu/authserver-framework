using System.Diagnostics;
using AuthServer.Authorization;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Authorize.Abstractions;
using AuthServer.Cache.Abstractions;
using AuthServer.Cache.Entities;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Metrics.Abstractions;
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
    private readonly IMetricService _metricService;

    public AuthorizeRequestValidator(
        ICachedClientStore cachedClientStore,
        IServerTokenDecoder serverTokenDecoder,
        IAuthorizeInteractionService authorizeInteractionService,
        ISecureRequestService secureRequestService,
        IOptionsSnapshot<DiscoveryDocument> discoveryDocumentOptions,
        INonceRepository nonceRepository,
        IClientRepository clientRepository,
        IAuthorizationGrantRepository authorizationGrantRepository,
        IMetricService metricService,
        IAuthorizationDetailValidator? authorizationDetailValidator = null)
        : base(nonceRepository, serverTokenDecoder, discoveryDocumentOptions, authorizationGrantRepository, clientRepository, authorizationDetailValidator)
    {
        _cachedClientStore = cachedClientStore;
        _authorizeInteractionService = authorizeInteractionService;
        _secureRequestService = secureRequestService;
        _metricService = metricService;
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

    private static ProcessError? ValidateCode(AuthorizeRequest request)
    {
        if (!HasValidCodeChallengeMethod(request.CodeChallengeMethod, request.ResponseType))
        {
            return AuthorizeError.InvalidCodeChallengeMethod;
        }

        if (!HasValidCodeChallenge(request.CodeChallenge, request.ResponseType))
        {
            return AuthorizeError.InvalidCodeChallenge;
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

        var nonceValidationResult = await ValidateNonce(request, cancellationToken);
        if (nonceValidationResult is not null)
        {
            return nonceValidationResult;
        }

        var codeValidationResult = ValidateCode(request);
        if (codeValidationResult is not null)
        {
            return codeValidationResult;
        }

        var authorizationParametersValidationResult = await ValidateAuthorizationParameters(request, cachedClient, cancellationToken);
        if (authorizationParametersValidationResult is not null)
        {
            return authorizationParametersValidationResult;
        }

        var openIdConnectCoreParametersValidationResult = await ValidateOpenIdConnectCoreParameters(request, cancellationToken);
        if (openIdConnectCoreParametersValidationResult is not null)
        {
            return openIdConnectCoreParametersValidationResult;
        }

        var grantValidationResult = await ValidateGrant(request, cachedClient, cancellationToken);
        if (grantValidationResult is not null)
        {
            return grantValidationResult;
        }

        if (!HasValidDPoP(request.DPoPJkt, null, cachedClient.RequireDPoPBoundAccessTokens, request.ResponseType))
        {
            return AuthorizeError.InvalidDPoPJkt;
        }

        return null;
    }

    private async Task<ProcessError?> ValidateGrant(AuthorizeRequest request, CachedClient cachedClient, CancellationToken cancellationToken)
    {
        if (!HasValidGrantManagementAction(request.GrantId, request.GrantManagementAction, cachedClient))
        {
            return AuthorizeError.InvalidGrantManagement;
        }

        if (!await HasValidGrantId(request.GrantId, cachedClient.Id, cancellationToken))
        {
            return AuthorizeError.InvalidGrantId;
        }

        return null;
    }

    private async Task<ProcessError?> ValidateNonce(AuthorizeRequest request, CancellationToken cancellationToken)
    {
        if (!HasValidNonce(request.Nonce, request.ResponseType))
        {
            return AuthorizeError.InvalidNonce;
        }

        if (!await HasUniqueNonce(request.Nonce!, cancellationToken))
        {
            return AuthorizeError.ReplayNonce;
        }

        return null;
    }

    private async Task<ProcessError?> ValidateAuthorizationParameters(AuthorizeRequest request, CachedClient cachedClient, CancellationToken cancellationToken)
    {
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

        var authorizationDetailsValidationResult = await ValidateAuthorizationDetails(request.AuthorizationDetails, cachedClient, cancellationToken);
        if (!authorizationDetailsValidationResult.IsValid)
        {
            return authorizationDetailsValidationResult.Error switch
            {
                AuthorizationDetailsError.NotSupported => AuthorizeError.NotSupportedAuthorizationDetails,
                AuthorizationDetailsError.Invalid => AuthorizeError.InvalidAuthorizationDetails,
                AuthorizationDetailsError.NotAuthorizedForClient => AuthorizeError.UnauthorizedAuthorizationDetailsForClient,
                AuthorizationDetailsError.NotAuthorizedForResource => AuthorizeError.UnauthorizedAuthorizationDetailsForResource,
                _ => throw new ArgumentOutOfRangeException($"error is not supported {authorizationDetailsValidationResult}")
            };
        }

        return null;
    }

    private async Task<ProcessError?> ValidateOpenIdConnectCoreParameters(AuthorizeRequest request, CancellationToken cancellationToken)
    {
        if (!HasValidDisplay(request.Display))
        {
            return AuthorizeError.InvalidDisplay;
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

        return null;
    }

    // This must first be deduced after successful validation of all input from the request
    private async Task<ProcessResult<AuthorizeValidatedRequest, ProcessError>> ValidateForInteraction(AuthorizeRequest request, CancellationToken cancellationToken)
    {
        var stopWatch = Stopwatch.StartNew();
        var interactionResult = await _authorizeInteractionService.GetInteractionResult(request, cancellationToken);
        stopWatch.Stop();

        _metricService.AddAuthorizeInteraction(
            stopWatch.ElapsedMilliseconds,
            request.ClientId!,
            interactionResult.GetPrompt(),
            interactionResult.AuthenticationKind);

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
            AuthorizationDetails = request.AuthorizationDetails,
            ClientId = request.ClientId!,
            Nonce = request.Nonce,
            RedirectUri = request.RedirectUri,
            RequestUri = request.RequestUri,
            DPoPJkt = request.DPoPJkt
        };
    }
}