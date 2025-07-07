using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Helpers;
using AuthServer.Tests.Core;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest;
public class RefreshTokenIntegrationTest : BaseIntegrationTest
{
    public RefreshTokenIntegrationTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
        : base(factory, testOutputHelper)
    {
    }

    [Fact]
    public async Task RefreshToken_DPoPRequestWithoutNonce_ExpectUseDPoPNonce()
    {
        // Arrange
        var weatherReadScope = await AddWeatherReadScope();
        var weatherClientSecret = CryptographyHelper.GetRandomString(16);
        var weatherClient = await AddWeatherClient(weatherClientSecret);

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("web-app")
            .WithRedirectUris(["https://webapp.authserver.dk/callback"])
            .WithGrantTypes([GrantTypeConstants.AuthorizationCode, GrantTypeConstants.RefreshToken])
            .WithScope([weatherReadScope, ScopeConstants.OpenId])
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();

        var grantId = await CreateAuthorizationGrant(registerResponse.ClientId, [AuthenticationMethodReferenceConstants.Password]);
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

        var dPoPNonce = await GetDPoPNonce(registerResponse.ClientId);
        var tokenResponse = await TokenEndpointBuilder
            .WithDPoP(dPoPNonce)
            .WithClientJwks(jwks)
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithCode(authorizeResponse.Code!)
            .WithCodeVerifier(proofKey.CodeVerifier)
            .WithResource([weatherClient.ClientUri!])
            .WithGrantType(GrantTypeConstants.AuthorizationCode)
            .Post();

        await ExpireDPoPNonce(dPoPNonce);

        // Act
        var refreshResponse = await TokenEndpointBuilder
            .WithDPoP(null)
            .WithClientJwks(jwks)
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithRefreshToken(tokenResponse.Response!.RefreshToken!)
            .WithGrantType(GrantTypeConstants.RefreshToken)
            .WithResource([weatherClient.ClientUri!])
            .WithScope([weatherReadScope])
            .Post();

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, refreshResponse.StatusCode);
        Assert.NotNull(refreshResponse.Error);
        Assert.Equal(ErrorCode.UseDPoPNonce, refreshResponse.Error.Error);
        Assert.Null(refreshResponse.Response);
        Assert.NotNull(refreshResponse.DPoPNonce);
    }

    [Fact]
    public async Task RefreshToken_RefreshTokenGrant_ExpectTokens()
    {
        // Arrange
        var weatherReadScope = await AddWeatherReadScope();
        var weatherClientSecret = CryptographyHelper.GetRandomString(16);
        var weatherClient = await AddWeatherClient(weatherClientSecret);

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("web-app")
            .WithRedirectUris(["https://webapp.authserver.dk/callback"])
            .WithGrantTypes([GrantTypeConstants.AuthorizationCode, GrantTypeConstants.RefreshToken])
            .WithScope([weatherReadScope, ScopeConstants.OpenId])
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();

        var grantId = await CreateAuthorizationGrant(registerResponse.ClientId, [AuthenticationMethodReferenceConstants.Password]);
        await Consent(UserConstants.SubjectIdentifier, registerResponse.ClientId, [weatherReadScope, ScopeConstants.OpenId], []);

        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithAuthorizeUser(grantId)
            .WithCodeChallenge(proofKey.CodeChallenge)
            .WithScope([weatherReadScope, ScopeConstants.OpenId])
            .WithResource([weatherClient.ClientUri!])
            .Get();

        var tokenResponse = await TokenEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithCode(authorizeResponse.Code!)
            .WithCodeVerifier(proofKey.CodeVerifier)
            .WithResource([weatherClient.ClientUri!])
            .WithGrantType(GrantTypeConstants.AuthorizationCode)
            .Post();

        // Act
        var refreshResponse = await TokenEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithRefreshToken(tokenResponse.Response!.RefreshToken!)
            .WithGrantType(GrantTypeConstants.RefreshToken)
            .WithResource([weatherClient.ClientUri!])
            .WithScope([weatherReadScope])
            .Post();

        // Assert
        Assert.NotNull(refreshResponse);
        Assert.Equal(weatherReadScope, refreshResponse.Response!.Scope);
        Assert.Equal(TokenTypeSchemaConstants.Bearer, refreshResponse.Response!.TokenType);
        Assert.Null(refreshResponse.Response!.RefreshToken);
        Assert.NotEqual(tokenResponse.Response!.RefreshToken, refreshResponse.Response!.RefreshToken);
        Assert.NotNull(refreshResponse.Response!.IdToken);
        Assert.NotNull(refreshResponse.Response!.AccessToken);
        Assert.Equal(registerResponse.AccessTokenExpiration, refreshResponse.Response!.ExpiresIn);
    }
}
