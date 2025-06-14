using System.Net;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Enums;
using AuthServer.Helpers;
using AuthServer.Repositories.Abstractions;
using AuthServer.Tests.Core;
using AuthServer.TokenDecoders;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;
using ProofKeyForCodeExchangeHelper = AuthServer.Tests.Core.ProofKeyForCodeExchangeHelper;

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

    [Fact]
    public async Task Token_DPoPRequestWithoutNonce_ExpectUseDPoPNonce()
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
    public async Task Token_AuthorizationCodeGrant_ExpectTokens()
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

        var grantId = await CreateAuthorizationGrant(registerResponse.ClientId, [AuthenticationMethodReferenceConstants.Password]);
        await Consent(UserConstants.SubjectIdentifier, registerResponse.ClientId, [ScopeConstants.UserInfo, ScopeConstants.OpenId, weatherReadScope], []);

        var proofKeyForCodeExchange = ProofKeyForCodeExchangeHelper.GetProofKeyForCodeExchange();
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithAuthorizeUser(grantId)
            .WithCodeChallenge(proofKeyForCodeExchange.CodeChallenge)
            .WithScope([weatherReadScope, ScopeConstants.UserInfo, ScopeConstants.OpenId])
            .WithResource([identityProviderClient.ClientUri!, weatherClient.ClientUri!])
            .Get();

        // Act
        var tokenResponse = await TokenEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithCode(authorizeResponse.Code!)
            .WithCodeVerifier(proofKeyForCodeExchange.CodeVerifier)
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

    [Fact]
    public async Task Token_RefreshTokenGrant_ExpectTokens()
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

        var proofKeyForCodeExchange = ProofKeyForCodeExchangeHelper.GetProofKeyForCodeExchange();
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithAuthorizeUser(grantId)
            .WithCodeChallenge(proofKeyForCodeExchange.CodeChallenge)
            .WithScope([weatherReadScope, ScopeConstants.OpenId])
            .WithResource([weatherClient.ClientUri!])
            .Get();

        var tokenResponse = await TokenEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithCode(authorizeResponse.Code!)
            .WithCodeVerifier(proofKeyForCodeExchange.CodeVerifier)
            .WithResource([weatherClient.ClientUri!])
            .WithGrantType(GrantTypeConstants.AuthorizationCode)
            .Post();

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

    [Fact]
    public async Task Token_ClientCredentialsGrantWithPrivateKeyJwt_ExpectAccessToken()
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
