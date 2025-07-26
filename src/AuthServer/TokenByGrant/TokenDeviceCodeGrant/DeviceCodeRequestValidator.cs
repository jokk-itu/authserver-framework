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

namespace AuthServer.TokenByGrant.TokenDeviceCodeGrant;
internal class DeviceCodeRequestValidator : BaseTokenValidator, IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>
{
    private readonly AuthorizationDbContext _authorizationDbContext;
    private readonly ICodeEncoder<EncodedDeviceCode> _deviceCodeEncoder;
    private readonly ICachedClientStore _cachedEntityStore;

    public DeviceCodeRequestValidator(
        AuthorizationDbContext authorizationDbContext,
        ICodeEncoder<EncodedDeviceCode> deviceCodeEncoder,
        IClientAuthenticationService clientAuthenticationService,
        IClientRepository clientRepository,
        ICachedClientStore cachedEntityStore,
        IConsentRepository consentRepository,
        IDPoPService dPoPService)
        : base(dPoPService, clientAuthenticationService, consentRepository, clientRepository)
    {
        _authorizationDbContext = authorizationDbContext;
        _deviceCodeEncoder = deviceCodeEncoder;
        _cachedEntityStore = cachedEntityStore;
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

        var clientAuthenticationResult = await AuthenticateClient(request.ClientAuthentications, cancellationToken);
        if (!clientAuthenticationResult.IsSuccess)
        {
            return clientAuthenticationResult.Error!;
        }

        var deviceCodeValidationResult = await ValidateDeviceCode(deviceCode, cancellationToken);
        if (!deviceCodeValidationResult.IsSuccess)
        {
            return deviceCodeValidationResult.Error!;
        }

        var clientId = clientAuthenticationResult.Value!;
        var cachedClient = await _cachedEntityStore.Get(clientId, cancellationToken);

        if (cachedClient.GrantTypes.All(x => x != request.GrantType))
        {
            return TokenError.UnauthorizedForGrantType;
        }

        var dPoPResult = await ValidateDPoP(request.DPoP, cachedClient, deviceCode.DPoPJkt, cancellationToken);
        if (dPoPResult?.Error is not null)
        {
            return dPoPResult.Error!;
        }

        var scopeValidationResult = await ValidateScope(deviceCode.Scope, request.Resource, deviceCodeValidationResult.Value!.DeviceCodeGrant!.Id, cachedClient, cancellationToken);
        if (!scopeValidationResult.IsSuccess)
        {
            return scopeValidationResult.Error!;
        }

        return new DeviceCodeValidatedRequest
        {
            ClientId = clientId,
            AuthorizationGrantId = deviceCodeValidationResult.Value!.DeviceCodeGrant.Id,
            DeviceCodeId = deviceCode.DeviceCodeId,
            DPoPJkt = deviceCode.DPoPJkt,
            Resource = request.Resource,
            Scope = scopeValidationResult.Value!
        };
    }

    private async Task<ProcessResult<DeviceCodeResult, ProcessError>> ValidateDeviceCode(EncodedDeviceCode deviceCode, CancellationToken cancellationToken)
    {
        var deviceCodeResult = await _authorizationDbContext
            .Set<DeviceCode>()
            .Where(x => x.Id == deviceCode.DeviceCodeId)
            .Select(x => new
            {
                DeviceCode = x,
                x.DeviceCodeGrant
            })
            .SingleOrDefaultAsync(cancellationToken);

        if (deviceCodeResult is null)
        {
            return TokenError.InvalidDeviceCode;
        }

        if (!Code.IsActive.Compile().Invoke(deviceCodeResult.DeviceCode))
        {
            return TokenError.DeviceCodeExpired;
        }

        if (!deviceCodeResult.DeviceCode.IsWithinInterval())
        {
            return TokenError.DeviceSlowDown(deviceCode.DeviceCodeId);
        }

        if (deviceCodeResult.DeviceCode.RevokedAt is not null)
        {
            return TokenError.DeviceAuthorizationDenied;
        }

        if (deviceCodeResult.DeviceCodeGrant is null)
        {
            return TokenError.DeviceAuthorizationPending(deviceCode.DeviceCodeId);
        }

        if (!AuthorizationGrant.IsActive.Compile().Invoke(deviceCodeResult.DeviceCodeGrant))
        {
            return TokenError.InvalidGrant;
        }

        return new DeviceCodeResult(deviceCodeResult.DeviceCode, deviceCodeResult.DeviceCodeGrant);
    }

    private sealed record DeviceCodeResult(DeviceCode DeviceCode, DeviceCodeGrant DeviceCodeGrant);
}
