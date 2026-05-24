using AuthServer.Authentication.Abstractions;
using AuthServer.Authorization;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Cache.Abstractions;
using AuthServer.Cache.Entities;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Options;
using AuthServer.Repositories.Abstractions;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.Extensions.Options;

namespace AuthServer.DeviceAuthorization;

internal class DeviceAuthorizationRequestValidator : BaseAuthorizeValidator, IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>
{
    private readonly ICachedClientStore _cachedClientStore;
    private readonly IClientAuthenticationService _clientAuthenticationService;
    private readonly ISecureRequestService _secureRequestService;
    private readonly IDPoPService _dPoPService;

    public DeviceAuthorizationRequestValidator(
        ICachedClientStore cachedClientStore,
        IClientAuthenticationService clientAuthenticationService,
        INonceRepository nonceRepository,
        IServerTokenDecoder serverTokenDecoder,
        IOptionsSnapshot<DiscoveryDocument> discoveryDocumentOptions,
        ISecureRequestService secureRequestService,
        IAuthorizationGrantRepository authorizationGrantRepository,
        IClientRepository clientRepository,
        IDPoPService dPoPService,
        IAuthorizationDetailValidator? authorizationDetailValidator = null)
        : base(nonceRepository, serverTokenDecoder, discoveryDocumentOptions, authorizationGrantRepository, clientRepository, authorizationDetailValidator)
    {
        _cachedClientStore = cachedClientStore;
        _clientAuthenticationService = clientAuthenticationService;
        _secureRequestService = secureRequestService;
        _dPoPService = dPoPService;
    }

    public async Task<ProcessResult<DeviceAuthorizationValidatedRequest, ProcessError>> Validate(DeviceAuthorizationRequest request, CancellationToken cancellationToken)
    {
        var isClientAuthenticationMethodInvalid = request.ClientAuthentications.Count != 1;
        if (isClientAuthenticationMethodInvalid)
        {
            return DeviceAuthorizationError.MultipleOrNoneClientMethod;
        }

        var clientAuthentication = request.ClientAuthentications.Single();
        var clientAuthenticationResult = await _clientAuthenticationService.AuthenticateClient(clientAuthentication, cancellationToken);
        if (!clientAuthenticationResult.IsAuthenticated || string.IsNullOrWhiteSpace(clientAuthenticationResult.ClientId))
        {
            return DeviceAuthorizationError.InvalidClient;
        }

        var cachedClient = await _cachedClientStore.Get(clientAuthenticationResult.ClientId, cancellationToken);
        if (!HasValidEmptyRequest(request.RequestObject, null, cachedClient.RequireSignedRequestObject))
        {
            return DeviceAuthorizationError.RequestRequiredAsRequestObject;
        }
        
        if (!string.IsNullOrEmpty(request.RequestObject))
        {
            var newRequest = await _secureRequestService.GetRequestByObject(request.RequestObject!, clientAuthenticationResult.ClientId, ClientTokenAudience.DeviceAuthorizationEndpoint, cancellationToken);
            if (newRequest is null)
            {
                return DeviceAuthorizationError.InvalidRequest;
            }

            request = new DeviceAuthorizationRequest(newRequest, request.ClientAuthentications, request.DPoP);
        }
        
        if (!HasDeviceCodeGrantType(cachedClient))
        {
            return DeviceAuthorizationError.UnauthorizedForGrant;
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

        if (!HasValidAcrValues(request.AcrValues))
        {
            return DeviceAuthorizationError.InvalidAcrValues;
        }
        
        var grantValidationResult = await ValidateGrant(request, cachedClient, cancellationToken);
        if (grantValidationResult is not null)
        {
            return grantValidationResult;
        }

        if (!HasValidDPoP(null, request.DPoP, cachedClient.RequireDPoPBoundAccessTokens, null))
        {
            return DeviceAuthorizationError.DPoPRequired;
        }

        var dPoPValidationResult = new DPoPValidationResult();
        if (!string.IsNullOrEmpty(request.DPoP))
        {
            dPoPValidationResult = await _dPoPService.ValidateDPoP(request.DPoP, cachedClient.Id, cancellationToken);

            if (dPoPValidationResult is { IsValid: false, RenewDPoPNonce: false })
            {
                return DeviceAuthorizationError.InvalidDPoP;
            }

            if (dPoPValidationResult is { IsValid: false, RenewDPoPNonce: true })
            {
                return DeviceAuthorizationError.RenewDPoPNonce(clientAuthenticationResult.ClientId);
            }
        }

        return new DeviceAuthorizationValidatedRequest
        {
            ClientId = clientAuthenticationResult.ClientId,
            AuthorizationGrantId = request.GrantId,
            GrantManagementAction = request.GrantManagementAction,
            CodeChallenge = request.CodeChallenge!,
            CodeChallengeMethod = request.CodeChallengeMethod!,
            Nonce = request.Nonce!,
            DPoPJkt = dPoPValidationResult.DPoPJkt,
            Scope = request.Scope,
            Resource = request.Resource,
            AuthorizationDetails = request.AuthorizationDetails,
            AcrValues = request.AcrValues
        };
    }

    private static ProcessError? ValidateCode(DeviceAuthorizationRequest request)
    {
        if (!HasValidCodeChallengeMethod(request.CodeChallengeMethod, null))
        {
            return DeviceAuthorizationError.InvalidCodeChallengeMethod;
        }

        if (!HasValidCodeChallenge(request.CodeChallenge, null))
        {
            return DeviceAuthorizationError.InvalidCodeChallenge;
        }

        return null;
    }

    private async Task<ProcessError?> ValidateGrant(DeviceAuthorizationRequest request, CachedClient cachedClient, CancellationToken cancellationToken)
    {
        if (!HasValidGrantManagementAction(request.GrantId, request.GrantManagementAction, cachedClient))
        {
            return DeviceAuthorizationError.InvalidGrantManagement;
        }

        if (!await HasValidGrantId(request.GrantId, cachedClient.Id, cancellationToken))
        {
            return DeviceAuthorizationError.InvalidGrantId;
        }

        return null;
    }

    private async Task<ProcessError?> ValidateNonce(DeviceAuthorizationRequest request, CancellationToken cancellationToken)
    {
        if (!HasValidNonce(request.Nonce, null))
        {
            return DeviceAuthorizationError.InvalidNonce;
        }

        if (!await HasUniqueNonce(request.Nonce!, cancellationToken))
        {
            return DeviceAuthorizationError.ReplayNonce;
        }

        return null;
    }

    private async Task<ProcessError?> ValidateAuthorizationParameters(DeviceAuthorizationRequest request, CachedClient cachedClient, CancellationToken cancellationToken)
    {
        if (!HasValidScope(request.Scope))
        {
            return DeviceAuthorizationError.InvalidOpenIdScope;
        }

        if (!HasAuthorizedScope(request.Scope, cachedClient))
        {
            return DeviceAuthorizationError.UnauthorizedScope;
        }

        if (request.Resource.Count == 0 && request.AuthorizationDetails.Count == 0)
        {
            return DeviceAuthorizationError.InvalidResource;
        }

        if (!await HasValidResource(request.Resource, request.Scope, cancellationToken))
        {
            return DeviceAuthorizationError.InvalidResource;
        }

        var authorizationDetailsValidationResult = await ValidateAuthorizationDetails(request.AuthorizationDetails, cachedClient, cancellationToken);
        if (authorizationDetailsValidationResult is not null)
        {
            return authorizationDetailsValidationResult switch
            {
                AuthorizationDetailsError.NotSupported => DeviceAuthorizationError.NotSupportedAuthorizationDetails,
                AuthorizationDetailsError.Invalid => DeviceAuthorizationError.InvalidAuthorizationDetails,
                AuthorizationDetailsError.NotAuthorizedForClient => DeviceAuthorizationError.UnauthorizedAuthorizationDetailsForClient,
                AuthorizationDetailsError.NotAuthorizedForResource => DeviceAuthorizationError.UnauthorizedAuthorizationDetailsForResource,
                _ => throw new ArgumentOutOfRangeException($"error is not supported {authorizationDetailsValidationResult}")
            };
        }
        
        return null;
    }
}