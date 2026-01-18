using AuthServer.Entities;
using AuthServer.Helpers;
using AuthServer.Repositories.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Repositories;

public class UserCodeRepositoryTest : BaseUnitTest
{
    public UserCodeRepositoryTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task RedeemUserCode_FreshUserCode_ExpectRedeemed()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var userCodeRepository = serviceProvider.GetRequiredService<IUserCodeRepository>();

        var deviceCode = new DeviceCode(300, 5);
        deviceCode.SetRawValue("value");
        var userCode = new UserCode(deviceCode, CryptographyHelper.GetUserCode());

        await AddEntity(userCode);

        // Act
        await userCodeRepository.RedeemUserCode(userCode.Value, CancellationToken.None);

        // Assert
        Assert.NotNull(userCode.RedeemedAt);
    }
}