using AuthServer.Constants;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Helpers;
using AuthServer.UserInterface;
using AuthServer.UserInterface.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.UserInterface;

public class DeviceCodeGrantServiceTest : BaseUnitTest
{
    public DeviceCodeGrantServiceTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("create")]
    public async Task HandleDeviceCodeAuthorizationGrant_CreateRequest_ExpectNewGrant(string? grantManagementAction)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var deviceCodeGrantService = serviceProvider.GetRequiredService<IDeviceCodeGrantService>();

        var subjectIdentifier = new SubjectIdentifier();
        await AddEntity(subjectIdentifier);

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            SubjectType = SubjectType.Public
        };
        await AddEntity(client);

        var deviceCode = new DeviceCode(300, 5);
        deviceCode.SetRawValue("raw_value");
        var userCode = new UserCode(deviceCode, CryptographyHelper.GetUserCode());
        await AddEntity(userCode);

        var deviceAuthorizeDto = new DeviceAuthorizeDto
        {
            GrantManagementAction = grantManagementAction,
            ClientId = client.Id,
            Scope = [ScopeConstants.OpenId],
            DeviceCodeId = deviceCode.Id,
            UserCodeId = userCode.Id
        };

        // Act
        var grantId = await deviceCodeGrantService.HandleDeviceCodeAuthorizationGrant(
            subjectIdentifier.Id,
            deviceAuthorizeDto,
            [AuthenticationMethodReferenceConstants.Password],
            CancellationToken.None);

        // Assert
        Assert.NotEmpty(grantId);
    }

    [Theory]
    [InlineData("merge")]
    [InlineData("replace")]
    public async Task HandleDeviceCodeAuthorizationGrant_UpdateRequest_ExpectUpdatedGrant(string? grantManagementAction)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var deviceCodeGrantService = serviceProvider.GetRequiredService<IDeviceCodeGrantService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            SubjectType = SubjectType.Public
        };
        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var deviceCode = new DeviceCode(300, 5);
        deviceCode.SetRawValue("raw_value");
        var grant = new DeviceCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);
        grant.DeviceCodes.Add(deviceCode);
        await AddEntity(grant);

        var userCode = new UserCode(deviceCode, CryptographyHelper.GetUserCode());
        await AddEntity(userCode);

        var authorizeRequestDto = new DeviceAuthorizeDto
        {
            GrantManagementAction = grantManagementAction,
            ClientId = client.Id,
            AuthorizationGrantId = grant.Id,
            Scope = [ScopeConstants.OpenId],
            DeviceCodeId = deviceCode.Id,
            UserCodeId = userCode.Id
        };

        // Act
        var grantId = await deviceCodeGrantService.HandleDeviceCodeAuthorizationGrant(
            subjectIdentifier.Id,
            authorizeRequestDto,
            [AuthenticationMethodReferenceConstants.Password],
            CancellationToken.None);

        // Assert
        Assert.Equal(grant.Id, grantId);
    }

    [Fact]
    public async Task RedeemUserCode_ValidUserCode_ExpectRedeemedUserCode()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var deviceCodeAuthorizationGrantService = serviceProvider.GetRequiredService<IDeviceCodeGrantService>();

        var deviceCode = new DeviceCode(300,5 );
        deviceCode.SetRawValue("raw_value");
        var userCode = new UserCode(deviceCode, CryptographyHelper.GetUserCode());
        await AddEntity(userCode);

        // Act
        await deviceCodeAuthorizationGrantService.RedeemUserCode(userCode.Value, CancellationToken.None);

        // Assert
        Assert.NotNull(userCode.RedeemedAt);
    }
}