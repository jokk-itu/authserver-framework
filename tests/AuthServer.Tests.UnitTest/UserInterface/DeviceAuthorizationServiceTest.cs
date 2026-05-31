using AuthServer.Authentication.Abstractions;
using AuthServer.Authentication.Models;
using AuthServer.Codes;
using AuthServer.Codes.Abstractions;
using AuthServer.Entities;
using AuthServer.Helpers;
using AuthServer.Repositories.Abstractions;
using AuthServer.Tests.Core;
using AuthServer.UserInterface.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.UserInterface;

public class DeviceAuthorizationServiceTest : BaseUnitTest
{
    public DeviceAuthorizationServiceTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task GetDeviceAuthorizeDto_InvalidUserCode_ExpectNull()
    {
        // Arrange
        var deviceCodeRepositoryMock = new Mock<IDeviceCodeRepository>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(deviceCodeRepositoryMock);
        });
        var deviceAuthorizeService = serviceProvider.GetRequiredService<IDeviceAuthorizeService>();

        const string userCode = "user_code";

        // Act
        var result = await deviceAuthorizeService.GetDeviceAuthorizeDto(userCode, CancellationToken.None);

        // Assert
        Assert.Null(result);
        deviceCodeRepositoryMock
            .Verify(x => x.GetDeviceCode(userCode, CancellationToken.None), Times.Once);
    }

    [Fact]
    public async Task GetDeviceAuthorizeDto_InvalidRawValue_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var deviceAuthorizeService = serviceProvider.GetRequiredService<IDeviceAuthorizeService>();

        var deviceCode = new DeviceCode(300, 5);
        deviceCode.SetRawValue("invalid_raw_value");
        var userCode = new UserCode(deviceCode, CryptographyHelper.GetUserCode());
        await AddEntity(userCode);

        // Act
        var result = await deviceAuthorizeService.GetDeviceAuthorizeDto(userCode.Value, CancellationToken.None);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task GetDeviceAuthorizeDto_ValidUserCode_ExpectDeviceAuthorizeDto()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var deviceAuthorizeService = serviceProvider.GetRequiredService<IDeviceAuthorizeService>();
        var deviceCodeEncoder = serviceProvider.GetRequiredService<ICodeEncoder<EncodedDeviceCode>>();

        var deviceCode = new DeviceCode(300, 5);
        var userCode = new UserCode(deviceCode, CryptographyHelper.GetUserCode());

        var encodedDeviceCode = new EncodedDeviceCode
        {
            ClientId = "client_id",
            Scope = ["scope"],
            CodeChallenge = "code_challenge",
            CodeChallengeMethod = "code_challenge_method",
            DeviceCodeId = deviceCode.Id,
            UserCodeId = userCode.Id,
            Resource = ["resource"]
        };
        var encodedDeviceCodeRawValue = deviceCodeEncoder.Encode(encodedDeviceCode);
        deviceCode.SetRawValue(encodedDeviceCodeRawValue);

        await AddEntity(userCode);

        // Act
        var result = await deviceAuthorizeService.GetDeviceAuthorizeDto(userCode.Value, CancellationToken.None);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(encodedDeviceCode.ClientId, result.ClientId);
        Assert.Equal(encodedDeviceCode.DeviceCodeId, result.DeviceCodeId);
        Assert.Equal(encodedDeviceCode.UserCodeId, result.UserCodeId);
        Assert.Equal(encodedDeviceCode.Scope, result.Scope);
        Assert.Empty(result.AcrValues);
        Assert.Null(result.AuthorizationGrantId);
        Assert.Null(result.GrantManagementAction);
    }

    [Fact]
    public async Task GetSubject_NoAuthenticatedUser_ExpectInvalidOperationException()
    {
        // Arrange
        var authenticatedUserAccessorMock = new Mock<IAuthenticatedUserAccessor>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authenticatedUserAccessorMock);
        });
        var deviceAuthorizeService = serviceProvider.GetRequiredService<IDeviceAuthorizeService>();

        // Act && Assert
        await Assert.ThrowsAsync<InvalidOperationException>(() => deviceAuthorizeService.GetSubject(CancellationToken.None));
    }

    [Fact]
    public async Task GetSubject_AuthenticatedUser_ExpectSubjectDto()
    {
        // Arrange
        var authenticatedUserAccessorMock = new Mock<IAuthenticatedUserAccessor>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authenticatedUserAccessorMock);
        });
        var deviceAuthorizeService = serviceProvider.GetRequiredService<IDeviceAuthorizeService>();

        var authenticatedUser = new AuthenticatedUser("subject", "grant");
        authenticatedUserAccessorMock
            .Setup(x => x.GetAuthenticatedUser())
            .ReturnsAsync(authenticatedUser)
            .Verifiable();

        // Act
        var subjectDto = await deviceAuthorizeService.GetSubject(CancellationToken.None);

        // Assert
        Assert.Equal(authenticatedUser.SubjectIdentifier, subjectDto.Subject);
        Assert.Equal(authenticatedUser.AuthorizationGrantId, subjectDto.GrantId);
        authenticatedUserAccessorMock.Verify();
    }
}