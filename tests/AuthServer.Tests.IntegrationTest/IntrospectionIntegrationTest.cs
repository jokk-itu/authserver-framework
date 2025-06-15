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

        var grantId = await CreateAuthorizationGrant(registerResponse.ClientId, [AuthenticationMethodReferenceConstants.Password]);
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
        Assert.True(introspectionResponse.Active);
        Assert.NotNull(introspectionResponse.JwtId);
        Assert.Equal(registerResponse.ClientId, introspectionResponse.ClientId);
        Assert.NotNull(introspectionResponse.ExpiresAt);
        Assert.Equal(DiscoveryDocument.Issuer, introspectionResponse.Issuer);
        Assert.NotNull(introspectionResponse.Audience);
        Assert.Single(introspectionResponse.Audience);
        Assert.Equal(weatherClient.ClientUri!, introspectionResponse.Audience.Single());
        Assert.NotNull(introspectionResponse.IssuedAt);
        Assert.NotNull(introspectionResponse.NotBefore);
        Assert.Equal(weatherReadScope, introspectionResponse.Scope);
        Assert.NotNull(introspectionResponse.Username);
        Assert.NotNull(introspectionResponse.AuthTime);
        Assert.NotNull(introspectionResponse.Acr);
        Assert.Equal(TokenTypeSchemaConstants.DPoP, introspectionResponse.TokenType);
        Assert.NotNull(introspectionResponse.Cnf);
        Assert.NotNull(introspectionResponse.Cnf.Jkt);

        Assert.NotNull(introspectionResponse.AccessControl);
        Assert.Equal(UserConstants.Roles, JsonSerializer.Deserialize<IEnumerable<string>>(introspectionResponse.AccessControl[ClaimNameConstants.Roles].ToString()!));
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
        Assert.True(introspectionResponse.Active);
        Assert.Equal(weatherReadScope, introspectionResponse.Scope);
        Assert.Equal([weatherClient.ClientUri], introspectionResponse.Audience);
        Assert.Equal(registerResponse.ClientId, introspectionResponse.ClientId);
        Assert.Equal(TokenTypeSchemaConstants.Bearer, introspectionResponse.TokenType);
        Assert.Null(introspectionResponse.Username);
        Assert.Equal(registerResponse.ClientId, introspectionResponse.Subject);
        Assert.Equal(DiscoveryDocument.Issuer, introspectionResponse.Issuer);
        Assert.NotNull(introspectionResponse.JwtId);
        Assert.Null(introspectionResponse.AccessControl);
        Assert.Null(introspectionResponse.Cnf);
    }
}