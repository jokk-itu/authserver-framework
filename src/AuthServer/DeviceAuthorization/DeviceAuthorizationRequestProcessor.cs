using AuthServer.Cache.Abstractions;
using AuthServer.Codes;
using AuthServer.Codes.Abstractions;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Helpers;
using AuthServer.Options;
using Microsoft.Extensions.Options;

namespace AuthServer.DeviceAuthorization;

internal class DeviceAuthorizationRequestProcessor : IRequestProcessor<DeviceAuthorizationValidatedRequest, DeviceAuthorizationResponse>
{
    private readonly ICodeEncoder<EncodedDeviceCode> _deviceCodeEncoder;
    private readonly AuthorizationDbContext _authorizationDbContext;
    private readonly IOptionsMonitor<UserInteraction> _userInteractionOptions;
    private readonly ICachedClientStore _cachedClientStore;

    public DeviceAuthorizationRequestProcessor(
        ICodeEncoder<EncodedDeviceCode> deviceCodeEncoder,
        AuthorizationDbContext authorizationDbContext,
        IOptionsMonitor<UserInteraction> userInteractionOptions,
        ICachedClientStore cachedClientStore)
    {
        _deviceCodeEncoder = deviceCodeEncoder;
        _authorizationDbContext = authorizationDbContext;
        _userInteractionOptions = userInteractionOptions;
        _cachedClientStore = cachedClientStore;
    }
    
    public async Task<DeviceAuthorizationResponse> Process(DeviceAuthorizationValidatedRequest request, CancellationToken cancellationToken)
    {
        var cachedClient = await _cachedClientStore.Get(request.ClientId, cancellationToken);
        const int interval = 5;
        var expiresOn = cachedClient.DeviceCodeExpiration!.Value;

        var deviceCode = new DeviceCode(expiresOn, interval);

        var userCodeValue = CryptographyHelper.GetUserCode();
        var userCode = new UserCode(deviceCode, userCodeValue);

        var encodedDeviceCode = _deviceCodeEncoder.Encode(new EncodedDeviceCode
        {
            AuthorizationGrantId = request.AuthorizationGrantId,
            GrantManagementAction = request.GrantManagementAction,
            CodeChallengeMethod = request.CodeChallengeMethod,
            CodeChallenge = request.CodeChallenge,
            Scope = request.Scope,
            Resource = request.Resource,
            AcrValues = request.AcrValues,
            DPoPJkt = request.DPoPJkt,
            DeviceCodeId = deviceCode.Id,
            UserCodeId = userCode.Id
        });

        deviceCode.SetRawValue(encodedDeviceCode);

        await _authorizationDbContext.AddAsync(userCode, cancellationToken);
        await _authorizationDbContext.SaveChangesAsync(cancellationToken);

        var verificationUri = _userInteractionOptions.CurrentValue.VerificationUri!;
        var verificationUriComplete = $"{verificationUri}?{Parameter.UserCode}={userCode.Value}";

        return new DeviceAuthorizationResponse
        {
            DeviceCode = encodedDeviceCode,
            UserCode = userCodeValue,
            VerificationUri = verificationUri,
            VerificationUriComplete = verificationUriComplete,
            ExpiresIn = expiresOn,
            Interval = interval
        };
    }
}