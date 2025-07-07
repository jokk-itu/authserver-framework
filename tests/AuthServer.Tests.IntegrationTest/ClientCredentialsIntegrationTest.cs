using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Enums;
using AuthServer.Helpers;
using AuthServer.Repositories.Abstractions;
using AuthServer.Tests.Core;
using AuthServer.TokenDecoders;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest;
public class ClientCredentialsIntegrationTest : BaseIntegrationTest
{
    public ClientCredentialsIntegrationTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
        : base(factory, testOutputHelper)
    {
    }

    [Fact]
    public async Task ClientCredentials_DPoPRequestWithoutNonce_ExpectUseDPoPNonce()
    {
        // Arrange
        var weatherReadScope = await AddWeatherReadScope();
        var weatherClientSecret = CryptographyHelper.GetRandomString(16);
        var weatherClient = await AddWeatherClient(weatherClientSecret);

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("web-app")
            .WithGrantTypes([GrantTypeConstants.ClientCredentials])
            .WithScope([weatherReadScope])
            .Post();

        // Act
        var jwks = ClientJwkBuilder.GetClientJwks();
        var tokenResponse = await TokenEndpointBuilder
            .WithGrantType(GrantTypeConstants.ClientCredentials)
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.ClientSecretBasic)
            .WithDPoP(null)
            .WithClientJwks(jwks)
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithScope([weatherReadScope])
            .WithResource([weatherClient.ClientUri!])
            .Post();

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.StatusCode);
        Assert.NotNull(tokenResponse.Error);
        Assert.Equal(ErrorCode.UseDPoPNonce, tokenResponse.Error.Error);
        Assert.Null(tokenResponse.Response);
        Assert.NotNull(tokenResponse.DPoPNonce);
    }

    [Fact]
    public async Task ClientCredentials_ClientCredentialsGrant_ExpectAccessToken()
    {
        // Arrange
        var weatherReadScope = await AddWeatherReadScope();
        var weatherClientSecret = CryptographyHelper.GetRandomString(16);
        var weatherClient = await AddWeatherClient(weatherClientSecret);
        var jwks = ClientJwkBuilder.GetClientJwks();

        var registerResponse = await RegisterEndpointBuilder
            .WithJwks(jwks.PublicJwks)
            .WithGrantTypes([GrantTypeConstants.ClientCredentials])
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.PrivateKeyJwt)
            .WithScope([weatherReadScope])
            .WithClientName("worker-app")
            .Post();

        var clientAssertion = JwtBuilder.GetPrivateKeyJwt(registerResponse.ClientId, jwks.PrivateJwks, ClientTokenAudience.TokenEndpoint);
        var nonceRepository = ServiceProvider.GetRequiredService<INonceRepository>();
        var nonce = await nonceRepository.CreateDPoPNonce(registerResponse.ClientId, CancellationToken.None);

        // Act
        var tokenResponse = await TokenEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithClientAssertion(clientAssertion)
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.PrivateKeyJwt)
            .WithGrantType(GrantTypeConstants.ClientCredentials)
            .WithScope([weatherReadScope])
            .WithResource([weatherClient.ClientUri!])
            .WithClientJwks(jwks)
            .WithDPoP(nonce)
            .Post();

        // Assert
        Assert.NotNull(tokenResponse);
        Assert.Equal(weatherReadScope, tokenResponse.Response!.Scope);
        Assert.Equal(TokenTypeSchemaConstants.DPoP, tokenResponse.Response!.TokenType);
        Assert.Null(tokenResponse.Response!.RefreshToken);
        Assert.Null(tokenResponse.Response!.IdToken);
        Assert.NotNull(tokenResponse.Response!.AccessToken);
        Assert.Equal(registerResponse.AccessTokenExpiration, tokenResponse.Response!.ExpiresIn);
    }
}