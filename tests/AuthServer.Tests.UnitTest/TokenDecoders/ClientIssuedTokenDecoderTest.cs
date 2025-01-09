using AuthServer.Tests.Core;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.TokenDecoders;

public class ClientIssuedTokenDecoderTest : BaseUnitTest
{
    public ClientIssuedTokenDecoderTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task Read_Jws_ExpectJsonWebToken()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<ITokenDecoder<ClientIssuedTokenDecodeArguments>>();
        var token = JwtBuilder.GetPrivateKeyJwt(
            "client_id",
            ClientJwkBuilder.GetClientJwks().PrivateJwks,
            ClientTokenAudience.TokenEndpoint);

        // Act
        var jsonWebToken = await tokenDecoder.Read(token);

        // Assert
        Assert.NotNull(jsonWebToken);
    }

    [Fact]
    public async Task Read_Jwe_ExpectJsonWebToken()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<ITokenDecoder<ClientIssuedTokenDecodeArguments>>();
        var token = JwtBuilder.GetEncryptedPrivateKeyJwt(
            "client_id",
            ClientJwkBuilder.GetClientJwks().PrivateJwks,
            ClientTokenAudience.TokenEndpoint);

        // Act
        var jsonWebToken = await tokenDecoder.Read(token);

        // Assert
        Assert.NotNull(jsonWebToken);
    }
}
