using System.Net;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Enums;
using AuthServer.Helpers;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest;
public class TokenIntegrationTest : BaseIntegrationTest
{
    public TokenIntegrationTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
        : base(factory, testOutputHelper)
    {
    }

    [Fact]
    public async Task Token_InvalidGrantType_ExpectUnsupportedGrantType()
    {
        // Arrange
        var weatherReadScope = await AddWeatherReadScope();
        var weatherClientSecret = CryptographyHelper.GetRandomString(16);
        var weatherClient = await AddWeatherClient(weatherClientSecret);

        var registerResponse = await RegisterEndpointBuilder
            .WithGrantTypes([GrantTypeConstants.ClientCredentials])
            .WithScope([weatherReadScope])
            .WithClientName("worker-app")
            .Post();

        // Act
        var tokenResponse = await TokenEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.ClientSecretBasic)
            .WithGrantType("invalid_grant_type")
            .WithScope([weatherReadScope])
            .WithResource([weatherClient.ClientUri!])
            .Post();

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.StatusCode);
        Assert.NotNull(tokenResponse.Error);
        Assert.Equal(ErrorCode.UnsupportedGrantType, tokenResponse.Error.Error);
    }
}
