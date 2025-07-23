using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Helpers;
using AuthServer.Tests.Core;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest;
public class AuthorizationCodeIntegrationTest : BaseIntegrationTest
{
    public AuthorizationCodeIntegrationTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
        : base(factory, testOutputHelper)
    {
    }

    [Fact]
    public async Task AuthorizationCode_DPoPRequestWithoutNonce_ExpectUseDPoPNonce()
    {
        // Arrange
        var weatherReadScope = await AddWeatherReadScope();
        var weatherClientSecret = CryptographyHelper.GetRandomString(16);
        var weatherClient = await AddWeatherClient(weatherClientSecret);

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("web-app")
            .WithRedirectUris(["https://webapp.authserver.dk/callback"])
            .WithScope([weatherReadScope, ScopeConstants.OpenId])
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();

        var grantId = await CreateAuthorizationCodeGrant(registerResponse.ClientId, [AuthenticationMethodReferenceConstants.Password]);
        await Consent(UserConstants.SubjectIdentifier, registerResponse.ClientId, [weatherReadScope, ScopeConstants.OpenId], []);

        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var jwks = ClientJwkBuilder.GetClientJwks();
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithAuthorizeUser(grantId)
            .WithDPoPJkt()
            .WithClientJwks(jwks)
            .WithCodeChallenge(proofKey.CodeChallenge)
            .WithScope([weatherReadScope, ScopeConstants.OpenId])
            .WithResource([weatherClient.ClientUri!])
            .Get();

        // Act
        var tokenResponse = await TokenEndpointBuilder
            .WithDPoP(null)
            .WithClientJwks(jwks)
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithCode(authorizeResponse.Code!)
            .WithCodeVerifier(proofKey.CodeVerifier)
            .WithResource([weatherClient.ClientUri!])
            .WithGrantType(GrantTypeConstants.AuthorizationCode)
            .Post();

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.StatusCode);
        Assert.NotNull(tokenResponse.Error);
        Assert.Equal(ErrorCode.UseDPoPNonce, tokenResponse.Error.Error);
        Assert.Null(tokenResponse.Response);
        Assert.NotNull(tokenResponse.DPoPNonce);
    }

    [Fact]
    public async Task AuthorizationCode_AuthorizationCodeGrant_ExpectTokens()
    {
        // Arrange
        var weatherReadScope = await AddWeatherReadScope();
        var weatherClientSecret = CryptographyHelper.GetRandomString(16);
        var weatherClient = await AddWeatherClient(weatherClientSecret);
        var identityProviderClient = await AddIdentityProviderClient();

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("web-app")
            .WithRedirectUris(["https://webapp.authserver.dk/callback"])
            .WithGrantTypes([GrantTypeConstants.AuthorizationCode])
            .WithScope([ScopeConstants.UserInfo, weatherReadScope, ScopeConstants.OpenId])
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();

        var grantId = await CreateAuthorizationCodeGrant(registerResponse.ClientId, [AuthenticationMethodReferenceConstants.Password]);
        await Consent(UserConstants.SubjectIdentifier, registerResponse.ClientId, [ScopeConstants.UserInfo, ScopeConstants.OpenId, weatherReadScope], []);

        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithAuthorizeUser(grantId)
            .WithCodeChallenge(proofKey.CodeChallenge)
            .WithScope([weatherReadScope, ScopeConstants.UserInfo, ScopeConstants.OpenId])
            .WithResource([identityProviderClient.ClientUri!, weatherClient.ClientUri!])
            .Get();

        // Act
        var tokenResponse = await TokenEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithCode(authorizeResponse.Code!)
            .WithCodeVerifier(proofKey.CodeVerifier)
            .WithResource([weatherClient.ClientUri!, identityProviderClient.ClientUri!])
            .WithGrantType(GrantTypeConstants.AuthorizationCode)
            .Post();

        // Assert
        Assert.NotNull(tokenResponse);
        Assert.Equal($"{weatherReadScope} {ScopeConstants.UserInfo} {ScopeConstants.OpenId}", tokenResponse.Response!.Scope);
        Assert.Equal(TokenTypeSchemaConstants.Bearer, tokenResponse.Response!.TokenType);
        Assert.Null(tokenResponse.Response!.RefreshToken);
        Assert.NotNull(tokenResponse.Response!.IdToken);
        Assert.NotNull(tokenResponse.Response!.AccessToken);
        Assert.Equal(registerResponse.AccessTokenExpiration, tokenResponse.Response!.ExpiresIn);
    }
}
