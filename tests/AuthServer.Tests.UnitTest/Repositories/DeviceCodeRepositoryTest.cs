using AuthServer.Entities;
using AuthServer.Helpers;
using AuthServer.Repositories.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Repositories;

public class DeviceCodeRepositoryTest : BaseUnitTest
{
    public DeviceCodeRepositoryTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task UpdateInterval_GivenDeviceCodeId_ExpectIncrementedInterval()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var deviceCodeRepository = serviceProvider.GetRequiredService<IDeviceCodeRepository>();

        var deviceCode = new DeviceCode(300, 5);
        deviceCode.SetRawValue("raw_value");
        await AddEntity(deviceCode);

        // Act
        await deviceCodeRepository.UpdateInterval(deviceCode.Id, CancellationToken.None);

        // Assert
        Assert.Equal(10, deviceCode.CurrentInterval);
    }

    [Fact]
    public async Task UpdatePoll_GivenDeviceCodeId_ExpectLatestPollUpdated()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var deviceCodeRepository = serviceProvider.GetRequiredService<IDeviceCodeRepository>();

        var deviceCode = new DeviceCode(300, 5);
        deviceCode.SetRawValue("raw_value");
        await AddEntity(deviceCode);

        // Act
        await deviceCodeRepository.UpdatePoll(deviceCode.Id, CancellationToken.None);

        // Assert
        Assert.NotNull(deviceCode.LatestPoll);
    }

    [Fact]
    public async Task GetDeviceCode_GivenInvalidUserCode_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var deviceCodeRepository = serviceProvider.GetRequiredService<IDeviceCodeRepository>();

        var deviceCode = new DeviceCode(300, 5);
        deviceCode.SetRawValue("raw_value");
        await AddEntity(deviceCode);

        // Act
        var queriedDeviceCode = await deviceCodeRepository.GetDeviceCode("invalid_user_code", CancellationToken.None);

        // Assert
        Assert.Null(queriedDeviceCode);
    }

    [Fact]
    public async Task GetDeviceCode_GivenValidUserCode_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var deviceCodeRepository = serviceProvider.GetRequiredService<IDeviceCodeRepository>();

        var deviceCode = new DeviceCode(300, 5);
        deviceCode.SetRawValue("raw_value");
        var userCode = new UserCode(deviceCode, CryptographyHelper.GetUserCode());
        await AddEntity(userCode);

        // Act
        var queriedDeviceCode = await deviceCodeRepository.GetDeviceCode(userCode.Value, CancellationToken.None);

        // Assert
        Assert.Equal(deviceCode, queriedDeviceCode);
    }
}