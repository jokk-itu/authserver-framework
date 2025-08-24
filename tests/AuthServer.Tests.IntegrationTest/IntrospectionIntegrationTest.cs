using System.Net;
using System.Text.Json;
using AuthServer.Constants;
using AuthServer.Enums;
using AuthServer.Helpers;
using AuthServer.Repositories.Abstractions;
using AuthServer.Tests.Core;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;
using ProofKeyGenerator = AuthServer.Tests.Core.ProofKeyGenerator;

namespace AuthServer.Tests.IntegrationTest;

public class IntrospectionIntegrationTest : BaseIntegrationTest
{
    public IntrospectionIntegrationTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
        : base(factory, testOutputHelper)
    {
    }

    [Fact]
    public async Task Introspection_InvalidTokenTypeHint_ExpectBadRequest()
    {
        // Arrange
        var weatherReadScope = await AddWeatherReadScope();

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("worker-app")
            .WithGrantTypes([GrantTypeConstants.ClientCredentials])
            .WithScope([weatherReadScope])
            .WithRequireReferenceToken()
            .Post();

        // Act
        var introspectionResponse = await IntrospectionEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithTokenTypeHint("invalid_token_type_hint")
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.ClientSecretBasic)
            .Post();

        // Arrange
        Assert.Equal(HttpStatusCode.BadRequest, introspectionResponse.StatusCode);
        Assert.NotNull(introspectionResponse.Error);
        Assert.Null(introspectionResponse.Response);
    }

    [Fact]
    public async Task Introspection_ActiveDPoPGrantAccessToken_ExpectActive()
    {
        // Arrange
        var weatherReadScope = await AddWeatherReadScope();
        var weatherClientSecret = CryptographyHelper.GetRandomString(16);
        var weatherClient = await AddWeatherClient(weatherClientSecret);

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("web-app")
            .WithRedirectUris(["https://webapp.authserver.dk/callback"])
            .WithGrantTypes([GrantTypeConstants.AuthorizationCode])
            .WithScope([weatherReadScope, ScopeConstants.OpenId])
            .WithRequireReferenceToken()
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();

        var grantId = await CreateAuthorizationCodeGrant(registerResponse.ClientId, [AuthenticationMethodReferenceConstants.Password]);
        await Consent(UserConstants.SubjectIdentifier, registerResponse.ClientId, [ScopeConstants.OpenId, weatherReadScope], []);

        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var jwks = ClientJwkBuilder.GetClientJwks();
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithAuthorizeUser(grantId)
            .WithCodeChallenge(proofKey.CodeChallenge)
            .WithScope([weatherReadScope, ScopeConstants.OpenId])
            .WithResource([weatherClient.ClientUri!])
            .WithDPoPJkt()
            .WithClientJwks(jwks)
            .Get();

        var nonceRepository = ServiceProvider.GetRequiredService<INonceRepository>();
        var nonce = await nonceRepository.CreateDPoPNonce(registerResponse.ClientId, CancellationToken.None);

        var tokenResponse = await TokenEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithCode(authorizeResponse.Code!)
            .WithCodeVerifier(proofKey.CodeVerifier)
            .WithResource([weatherClient.ClientUri!])
            .WithGrantType(GrantTypeConstants.AuthorizationCode)
            .WithDPoP(nonce)
            .WithClientJwks(jwks)
            .Post();

        // Act
        var introspectionResponse = await IntrospectionEndpointBuilder
            .WithClientId(weatherClient.Id)
            .WithClientSecret(weatherClientSecret)
            .WithToken(tokenResponse.Response!.AccessToken)
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.ClientSecretBasic)
            .Post();

        // Arrange
        Assert.Equal(HttpStatusCode.OK, introspectionResponse.StatusCode);
        Assert.Null(introspectionResponse.Error);
        Assert.NotNull(introspectionResponse.Response);
        var response = introspectionResponse.Response;

        Assert.True(response.Active);
        Assert.NotNull(response.JwtId);
        Assert.Equal(registerResponse.ClientId, response.ClientId);
        Assert.NotNull(response.ExpiresAt);
        Assert.Equal(DiscoveryDocument.Issuer, response.Issuer);
        Assert.NotNull(response.Audience);
        Assert.Single(response.Audience);
        Assert.Equal(weatherClient.ClientUri!, response.Audience.Single());
        Assert.NotNull(response.IssuedAt);
        Assert.NotNull(response.NotBefore);
        Assert.Equal(weatherReadScope, response.Scope);
        Assert.NotNull(response.Username);
        Assert.NotNull(response.AuthTime);
        Assert.NotNull(response.Acr);
        Assert.Equal(TokenTypeSchemaConstants.DPoP, response.TokenType);
        Assert.NotNull(response.Cnf);
        Assert.NotNull(response.Cnf.Jkt);

        Assert.NotNull(response.AccessControl);
        Assert.Equal(UserConstants.Roles, JsonSerializer.Deserialize<IEnumerable<string>>(response.AccessControl[ClaimNameConstants.Roles].ToString()!));
    }

    [Fact]
    public async Task Introspection_ActiveBearerClientAccessToken_ExpectActive()
    {
        // Arrange
        var weatherReadScope = await AddWeatherReadScope();
        var weatherClientSecret = CryptographyHelper.GetRandomString(16);
        var weatherClient = await AddWeatherClient(weatherClientSecret);

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("worker-app")
            .WithGrantTypes([GrantTypeConstants.ClientCredentials])
            .WithScope([weatherReadScope])
            .WithRequireReferenceToken()
            .Post();

        var tokenResponse = await TokenEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithGrantType(GrantTypeConstants.ClientCredentials)
            .WithResource([weatherClient.ClientUri!])
            .WithScope([weatherReadScope])
            .Post();

        // Act
        var introspectionResponse = await IntrospectionEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithToken(tokenResponse.Response!.AccessToken)
            .WithTokenTypeHint(TokenTypeConstants.AccessToken)
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.ClientSecretBasic)
            .Post();

        // Arrange
        Assert.Equal(HttpStatusCode.OK, introspectionResponse.StatusCode);
        Assert.Null(introspectionResponse.Error);
        Assert.NotNull(introspectionResponse.Response);
        var response = introspectionResponse.Response;

        Assert.True(response.Active);
        Assert.Equal(weatherReadScope, response.Scope);
        Assert.Equal([weatherClient.ClientUri], response.Audience);
        Assert.Equal(registerResponse.ClientId, response.ClientId);
        Assert.Equal(TokenTypeSchemaConstants.Bearer, response.TokenType);
        Assert.Null(response.Username);
        Assert.Equal(registerResponse.ClientId, response.Subject);
        Assert.Equal(DiscoveryDocument.Issuer, response.Issuer);
        Assert.NotNull(response.JwtId);
        Assert.Null(response.AccessControl);
        Assert.Null(response.Cnf);
        Assert.Null(response.Act);
        Assert.Null(response.MayAct);
    }
}