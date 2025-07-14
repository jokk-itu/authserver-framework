using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.DeviceAuthorization;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Extensions;
using AuthServer.Helpers;
using AuthServer.Tests.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.DeviceAuthorization;
public class DeviceAuthorizationRequestProcessorTest : BaseUnitTest
{
    public DeviceAuthorizationRequestProcessorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task Process_CreateDeviceCodeAndUserCode_ExpectDeviceCodeAndUserCode()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var processor = serviceProvider
            .GetRequiredService<IRequestProcessor<DeviceAuthorizationValidatedRequest, DeviceAuthorizationResponse>>();

        var client = new Client("tv-app", ApplicationType.Native, TokenEndpointAuthMethod.None,
            3600, 60)
        {
            DeviceCodeExpiration = 300
        };

        await AddEntity(client);

        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();

        var validatedRequest = new DeviceAuthorizationValidatedRequest
        {
            ClientId = client.Id,
            CodeChallenge = proofKey.CodeChallenge,
            CodeChallengeMethod = proofKey.CodeChallengeMethod,
            Nonce = CryptographyHelper.GetRandomString(16),
            AcrValues = [ LevelOfAssuranceLow ],
            GrantManagementAction = GrantManagementActionConstants.Create,
            Resource = [ "https://api.authserver.dk" ],
            Scope = [ ScopeConstants.OpenId, ScopeConstants.UserInfo ]
        };

        // Act
        var response = await processor.Process(validatedRequest, CancellationToken.None);

        // Assert
        Assert.NotNull(response.DeviceCode);
        Assert.NotNull(response.UserCode);

        var deviceCode = Assert.Single(
            IdentityContext.Set<DeviceCode>(),
            x => x.RawValue == response.DeviceCode);

        var userCode = Assert.Single(
            IdentityContext.Set<UserCode>().Include(x => x.DeviceCode),
            x => x.Value == response.UserCode);

        Assert.Equal(deviceCode, userCode.DeviceCode);

        Assert.Equal(deviceCode.ExpiresAt.ToUnixTimeSeconds() - deviceCode.IssuedAt.ToUnixTimeSeconds(), response.ExpiresIn);

        Assert.Equal(deviceCode.CurrentInterval, response.Interval);

        Assert.Equal(UserInteraction.VerificationUri, response.VerificationUri);
        Assert.Equal($"{UserInteraction.VerificationUri}?{Parameter.UserCode}={response.UserCode}", response.VerificationUriComplete);
    }
}
