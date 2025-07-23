using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Enums;
using AuthServer.Helpers;
using AuthServer.Tests.Core;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest;
public class DeviceAuthorizationIntegrationTest : BaseIntegrationTest
{
    public DeviceAuthorizationIntegrationTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
        : base(factory, testOutputHelper)
    {
    }

    [Fact]
    public async Task DeviceAuthorization_DPoPRequestWithoutNonce_ExpectUseDPoPNonce()
    {
        // Arrange
        var weatherReadScope = await AddWeatherReadScope();
        var weatherClientSecret = CryptographyHelper.GetRandomString(16);
        var weatherClient = await AddWeatherClient(weatherClientSecret);

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("tv-app")
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.None)
            .WithApplicationType(ApplicationTypeConstants.Native)
            .WithGrantTypes([GrantTypeConstants.DeviceCode])
            .WithScope([weatherReadScope, ScopeConstants.OpenId])
            .Post();

        // Act
        var jwks = ClientJwkBuilder.GetClientJwks();
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var deviceAuthorizationResponse = await DeviceAuthorizationEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithScope(registerResponse.Scope)
            .WithCodeChallenge(proofKey.CodeChallenge)
            .WithCodeChallengeMethod(proofKey.CodeChallengeMethod)
            .WithResource([weatherClient.ClientUri!])
            .WithDPoP(null)
            .WithClientJwks(jwks)
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.None)
            .Post();

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, deviceAuthorizationResponse.StatusCode);
        Assert.NotNull(deviceAuthorizationResponse.Error);
        Assert.Equal(ErrorCode.UseDPoPNonce, deviceAuthorizationResponse.Error.Error);
        Assert.Null(deviceAuthorizationResponse.Response);
        Assert.NotNull(deviceAuthorizationResponse.DPoPNonce);
    }

    [Fact]
    public async Task DeviceAuthorization_ValidRequest_ExpectDeviceCode()
    {
        // Arrange
        var weatherReadScope = await AddWeatherReadScope();
        var weatherClientSecret = CryptographyHelper.GetRandomString(16);
        var weatherClient = await AddWeatherClient(weatherClientSecret);

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("tv-app")
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.None)
            .WithApplicationType(ApplicationTypeConstants.Native)
            .WithGrantTypes([GrantTypeConstants.DeviceCode])
            .WithScope([weatherReadScope, ScopeConstants.OpenId])
            .WithDeviceCodeExpiration(120)
            .Post();

        // Act
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var deviceAuthorizationResponse = await DeviceAuthorizationEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithScope(registerResponse.Scope)
            .WithCodeChallenge(proofKey.CodeChallenge)
            .WithCodeChallengeMethod(proofKey.CodeChallengeMethod)
            .WithResource([weatherClient.ClientUri!])
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.None)
            .Post();

        // Assert
        Assert.Equal(HttpStatusCode.OK, deviceAuthorizationResponse.StatusCode);
        Assert.Null(deviceAuthorizationResponse.Error);
        Assert.NotNull(deviceAuthorizationResponse.Response);
        Assert.NotNull(deviceAuthorizationResponse.Response.DeviceCode);
        Assert.NotNull(deviceAuthorizationResponse.Response.UserCode);
        Assert.Equal(registerResponse.DeviceCodeExpiration, deviceAuthorizationResponse.Response.ExpiresIn);
        Assert.Equal(5, deviceAuthorizationResponse.Response.Interval);
    }
}