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

        if (!HasValidNonce(request.Nonce))
        {
            return DeviceAuthorizationError.InvalidNonce;
        }
        
        if (!await HasUniqueNonce(request.Nonce!, cancellationToken))
        {
            return DeviceAuthorizationError.ReplayNonce;
        }

        if (!HasValidCodeChallengeMethod(request.CodeChallengeMethod))
        {
            return DeviceAuthorizationError.InvalidCodeChallengeMethod;
        }

        if (!HasValidCodeChallenge(request.CodeChallenge))
        {
            return DeviceAuthorizationError.InvalidCodeChallenge;
        }

        if (!HasValidScope(request.Scope))
        {
            return DeviceAuthorizationError.InvalidOpenIdScope;
        }

        if (!HasAuthorizedScope(request.Scope, cachedClient))
        {
            return DeviceAuthorizationError.UnauthorizedScope;
        }

        if (!await HasValidResource(request.Resource, request.Scope, cancellationToken))
        {
            return DeviceAuthorizationError.InvalidResource;
        }
        
        if (!HasValidAcrValues(request.AcrValues))
        {
            return DeviceAuthorizationError.InvalidAcrValues;
        }
        
        if (!HasValidGrantManagementAction(request.GrantId, request.GrantManagementAction))
        {
            return DeviceAuthorizationError.InvalidGrantManagement;
        }

        if (!await HasValidGrantId(request.GrantId, cachedClient.Id, cancellationToken))
        {
            return DeviceAuthorizationError.InvalidGrantId;
        }

        if (!HasValidDPoP(null, request.DPoP, cachedClient.RequireDPoPBoundAccessTokens))
        {
            return DeviceAuthorizationError.DPoPRequired;
        }

        var dPoPValidationResult = new DPoPValidationResult();
        if (!string.IsNullOrEmpty(request.DPoP))
        {
            dPoPValidationResult = await _dPoPService.ValidateDPoP(request.DPoP, cachedClient.Id, cancellationToken);

            if (dPoPValidationResult is { IsValid: false, DPoPNonce: null, RenewDPoPNonce: false })
            {
                return DeviceAuthorizationError.InvalidDPoP;
            }

            if (dPoPValidationResult is { IsValid: false, DPoPNonce: not null })
            {
                return DeviceAuthorizationError.UseDPoPNonce(dPoPValidationResult.DPoPNonce!);
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
            AcrValues = request.AcrValues
        };
    }
}