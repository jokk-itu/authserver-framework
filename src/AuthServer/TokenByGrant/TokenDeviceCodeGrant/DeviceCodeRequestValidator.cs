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
using AuthServer.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthServer.TokenByGrant.TokenDeviceCodeGrant;
internal class DeviceCodeRequestValidator : BaseTokenValidator, IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>
{
    private readonly AuthorizationDbContext _authorizationDbContext;
    private readonly ICodeEncoder<EncodedDeviceCode> _deviceCodeEncoder;
    private readonly ICachedClientStore _cachedEntityStore;
    private readonly IOptionsMonitor<TokenValidationOptions> _tokenValidationOptions;

    public DeviceCodeRequestValidator(
        AuthorizationDbContext authorizationDbContext,
        ICodeEncoder<EncodedDeviceCode> deviceCodeEncoder,
        IClientAuthenticationService clientAuthenticationService,
        ICachedClientStore cachedEntityStore,
        IOptionsMonitor<TokenValidationOptions> tokenValidationOptions,
        IDPoPService dPoPService,
        IScopeResourceService scopeResourceService)
        : base(dPoPService, clientAuthenticationService, scopeResourceService)
    {
        _authorizationDbContext = authorizationDbContext;
        _deviceCodeEncoder = deviceCodeEncoder;
        _cachedEntityStore = cachedEntityStore;
        _tokenValidationOptions = tokenValidationOptions;
    }

    public async Task<ProcessResult<DeviceCodeValidatedRequest, ProcessError>> Validate(TokenRequest request, CancellationToken cancellationToken)
    {
        if (request.GrantType != GrantTypeConstants.DeviceCode)
        {
            return TokenError.UnsupportedGrantType;
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

        return new DeviceCodeValidatedRequest
        {
            ClientId = clientId,
            AuthorizationGrantId = deviceCodeValidationResult.Value!.AuthorizationGrantId,
            DeviceCodeId = deviceCode.DeviceCodeId,
            DPoPJkt = deviceCode.DPoPJkt,
            Resource = deviceCode.Resource,
            Scope = deviceCode.Scope
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

        if (deviceCodeResult.DeviceCode.RedeemedAt is not null)
        {
            return TokenError.DeviceCodeRedeemed;
        }

        if (deviceCodeResult.DeviceCode.ExpiresAt.Add(_tokenValidationOptions.CurrentValue.ClockSkew) < DateTime.UtcNow)
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

        return new DeviceCodeResult(deviceCodeResult.DeviceCodeGrant.Id);
    }

    private sealed record DeviceCodeResult(string AuthorizationGrantId);
}
