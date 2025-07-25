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
using AuthServer.Extensions;
using AuthServer.Repositories.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.TokenByGrant.TokenDeviceCodeGrant;
internal class DeviceCodeRequestValidator : IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>
{
    private readonly AuthorizationDbContext _authorizationDbContext;
    private readonly ICodeEncoder<EncodedDeviceCode> _deviceCodeEncoder;
    private readonly IClientAuthenticationService _clientAuthenticationService;
    private readonly IClientRepository _clientRepository;
    private readonly ICachedClientStore _cachedEntityStore;
    private readonly IConsentRepository _consentGrantRepository;
    private readonly IDPoPService _dPoPService;

    public DeviceCodeRequestValidator(
        AuthorizationDbContext authorizationDbContext,
        ICodeEncoder<EncodedDeviceCode> deviceCodeEncoder,
        IClientAuthenticationService clientAuthenticationService,
        IClientRepository clientRepository,
        ICachedClientStore cachedEntityStore,
        IConsentRepository consentGrantRepository,
        IDPoPService dPoPService)
    {
        _authorizationDbContext = authorizationDbContext;
        _deviceCodeEncoder = deviceCodeEncoder;
        _clientAuthenticationService = clientAuthenticationService;
        _clientRepository = clientRepository;
        _cachedEntityStore = cachedEntityStore;
        _consentGrantRepository = consentGrantRepository;
        _dPoPService = dPoPService;
    }

    public async Task<ProcessResult<DeviceCodeValidatedRequest, ProcessError>> Validate(TokenRequest request, CancellationToken cancellationToken)
    {
        if (request.GrantType != GrantTypeConstants.DeviceCode)
        {
            return TokenError.UnsupportedGrantType;
        }

        if (request.Resource.Count == 0)
        {
            return TokenError.InvalidResource;
        }

        var deviceCode = _deviceCodeEncoder.Decode(request.DeviceCode);
        if (deviceCode is null)
        {
            return TokenError.InvalidDeviceCode;
        }

        var isCodeVerifierValid = ProofKeyHelper.IsCodeVerifierValid(request.CodeVerifier, deviceCode.CodeChallenge, deviceCode.CodeChallengeMethod);
        if (!isCodeVerifierValid)
        {
            return TokenError.InvalidCodeVerifier;
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

        var deviceCodeQuery = await _authorizationDbContext
            .Set<DeviceCode>()
            .Where(x => x.Id == deviceCode.DeviceCodeId)
            .Select(x => new
            {
                DeviceCode = x,
                Grant = x.DeviceCodeGrant
            })
            .SingleOrDefaultAsync(cancellationToken);

        if (deviceCodeQuery is null)
        {
            return TokenError.InvalidDeviceCode;
        }

        if (!Code.IsActive.Compile().Invoke(deviceCodeQuery.DeviceCode))
        {
            return TokenError.DeviceCodeExpired;
        }

        if (!deviceCodeQuery.DeviceCode.IsWithinInterval())
        {
            return TokenError.DeviceSlowDown(deviceCode.DeviceCodeId);
        }

        if (deviceCodeQuery.DeviceCode.RevokedAt is not null)
        {
            return TokenError.DeviceAuthorizationDenied;
        }

        if (deviceCodeQuery.Grant is null)
        {
            return TokenError.DeviceAuthorizationPending(deviceCode.DeviceCodeId);
        }

        if (!AuthorizationGrant.IsActive.Compile().Invoke(deviceCodeQuery.Grant))
        {
            return TokenError.InvalidGrant;
        }

        var clientId = clientAuthenticationResult.ClientId!;
        var cachedClient = await _cachedEntityStore.Get(clientId, cancellationToken);

        if (cachedClient.GrantTypes.All(x => x != request.GrantType))
        {
            return TokenError.UnauthorizedForGrantType;
        }

        var isDPoPRequired = cachedClient.RequireDPoPBoundAccessTokens || deviceCode.DPoPJkt is not null;
        if (isDPoPRequired && string.IsNullOrEmpty(request.DPoP))
        {
            return TokenError.DPoPRequired;
        }

        if (!string.IsNullOrEmpty(request.DPoP))
        {
            var dPoPValidationResult = await _dPoPService.ValidateDPoP(request.DPoP, clientId, cancellationToken);
            if (dPoPValidationResult is { IsValid: false, RenewDPoPNonce: false })
            {
                return TokenError.InvalidDPoP;
            }

            if (dPoPValidationResult is { IsValid: false, RenewDPoPNonce: true })
            {
                return TokenError.RenewDPoPNonce(clientId);
            }

            if (dPoPValidationResult.DPoPJkt != deviceCode.DPoPJkt)
            {
                return TokenError.InvalidDPoPJktMatch;
            }
        }

        // Request.Scopes cannot be given during device_code grant
        var scope = deviceCode.Scope;

        // Check scope again, as the authorized scope can change
        if (scope.IsNotSubset(cachedClient.Scopes))
        {
            return TokenError.UnauthorizedForScope;
        }

        if (cachedClient.RequireConsent)
        {
            var grantConsentScopes = await _consentGrantRepository.GetGrantConsentedScopes(deviceCodeQuery.Grant.Id, cancellationToken);
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

        return new DeviceCodeValidatedRequest
        {
            ClientId = clientId,
            AuthorizationGrantId = deviceCodeQuery.Grant.Id,
            DeviceCodeId = deviceCode.DeviceCodeId,
            DPoPJkt = deviceCode.DPoPJkt,
            Resource = request.Resource,
            Scope = scope
        };
    }
}
