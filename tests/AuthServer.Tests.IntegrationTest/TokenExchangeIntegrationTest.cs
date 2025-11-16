using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Helpers;
using AuthServer.Tests.Core;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest;
public class TokenExchangeIntegrationTest : BaseIntegrationTest
{
    public TokenExchangeIntegrationTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
        : base(factory, testOutputHelper)
    {
    }

    [Fact]
    public async Task TokenExchange_DPoPRequestWithoutNonce_ExpectUseDPoPNonce()
    {
        // Arrange
        var weatherReadScope = await AddWeatherReadScope();
        var weatherClientSecret = CryptographyHelper.GetRandomString(16);
        var weatherClient = await AddWeatherClient(weatherClientSecret);

        var originalClientRegisterResponse = await RegisterEndpointBuilder
            .WithClientName("web-app")
            .WithGrantTypes([GrantTypeConstants.ClientCredentials])
            .WithScope([weatherReadScope])
            .Post();

        var impersonatorClientRegisterResponse = await RegisterEndpointBuilder
            .WithClientName("impersonater-api")
            .WithGrantTypes([GrantTypeConstants.TokenExchange])
            .WithScope([weatherReadScope])
            .Post();

        var tokenResponse = await TokenEndpointBuilder
            .WithClientId(originalClientRegisterResponse.ClientId)
            .WithClientSecret(originalClientRegisterResponse.ClientSecret!)
            .WithResource([weatherClient.ClientUri!])
            .WithScope([weatherReadScope])
            .WithGrantType(GrantTypeConstants.ClientCredentials)
            .Post();

        var jwks = ClientJwkBuilder.GetClientJwks();

        // Act
        var tokenExchangeResponse = await TokenEndpointBuilder
            .WithDPoP(null)
            .WithClientJwks(jwks)
            .WithClientId(impersonatorClientRegisterResponse.ClientId)
            .WithClientSecret(impersonatorClientRegisterResponse.ClientSecret!)
            .WithGrantType(GrantTypeConstants.TokenExchange)
            .WithResource([weatherClient.ClientUri!])
            .WithScope([weatherReadScope])
            .WithRequestedTokenType(TokenTypeIdentifier.AccessToken)
            .WithSubjectToken(tokenResponse.Response!.AccessToken)
            .WithSubjectTokenType(TokenTypeIdentifier.AccessToken)
            .Post();

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, tokenExchangeResponse.StatusCode);
        Assert.NotNull(tokenExchangeResponse.Error);
        Assert.Equal(ErrorCode.UseDPoPNonce, tokenExchangeResponse.Error.Error);
        Assert.Null(tokenExchangeResponse.Response);
        Assert.NotNull(tokenExchangeResponse.DPoPNonce);
    }

    [Fact]
    public async Task TokenExchange_ImpersonateAccessToken_ExpectImpersonatedAccessToken()
    {
        // Arrange
        var weatherReadScope = await AddWeatherReadScope();
        var weatherClientSecret = CryptographyHelper.GetRandomString(16);
        var weatherClient = await AddWeatherClient(weatherClientSecret);

        var originalClientRegisterResponse = await RegisterEndpointBuilder
            .WithClientName("web-app")
            .WithRedirectUris(["https://webapp.authserver.dk/callback"])
            .WithGrantTypes([GrantTypeConstants.AuthorizationCode])
            .WithScope([weatherReadScope, ScopeConstants.OpenId])
            .WithAccessTokenExpiration(300)
            .Post();

        var impersonatorClientRegisterResponse = await RegisterEndpointBuilder
            .WithClientName("impersonater-api")
            .WithGrantTypes([GrantTypeConstants.TokenExchange])
            .WithScope([weatherReadScope])
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();

        var grantId = await CreateAuthorizationCodeGrant(originalClientRegisterResponse.ClientId, [AuthenticationMethodReferenceConstants.Password]);
        await Consent(UserConstants.SubjectIdentifier, originalClientRegisterResponse.ClientId, [weatherReadScope, ScopeConstants.OpenId], []);

        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(originalClientRegisterResponse.ClientId)
            .WithAuthorizeUser(grantId)
            .WithCodeChallenge(proofKey.CodeChallenge)
            .WithScope([weatherReadScope, ScopeConstants.OpenId])
            .WithResource([weatherClient.ClientUri!])
            .Get();

        var tokenResponse = await TokenEndpointBuilder
            .WithClientId(originalClientRegisterResponse.ClientId)
            .WithClientSecret(originalClientRegisterResponse.ClientSecret!)
            .WithCode(authorizeResponse.Code!)
            .WithCodeVerifier(proofKey.CodeVerifier)
            .WithResource([weatherClient.ClientUri!])
            .WithGrantType(GrantTypeConstants.AuthorizationCode)
            .Post();

        // Act
        var tokenExchangeResponse = await TokenEndpointBuilder
            .WithClientId(impersonatorClientRegisterResponse.ClientId)
            .WithClientSecret(impersonatorClientRegisterResponse.ClientSecret!)
            .WithGrantType(GrantTypeConstants.TokenExchange)
            .WithResource([weatherClient.ClientUri!])
            .WithScope([weatherReadScope])
            .WithRequestedTokenType(TokenTypeIdentifier.AccessToken)
            .WithSubjectToken(tokenResponse.Response!.AccessToken)
            .WithSubjectTokenType(TokenTypeIdentifier.AccessToken)
            .Post();

        // Assert
        Assert.NotNull(tokenExchangeResponse);
        Assert.Equal(HttpStatusCode.OK, tokenExchangeResponse.StatusCode);
        Assert.Null(tokenExchangeResponse.Error);
        Assert.NotNull(tokenExchangeResponse.Response);
        Assert.Equal(TokenTypeIdentifier.AccessToken, tokenExchangeResponse.Response.IssuedTokenType);
        Assert.NotNull(tokenExchangeResponse.Response.AccessToken);
        Assert.Null(tokenExchangeResponse.Response.IdToken);
        Assert.Null(tokenExchangeResponse.Response.RefreshToken);
        Assert.Equal(TokenTypeSchemaConstants.Bearer, tokenExchangeResponse.Response.TokenType);
        Assert.Equal(originalClientRegisterResponse.AccessTokenExpiration, tokenExchangeResponse.Response.ExpiresIn);
        Assert.Equal(weatherReadScope, tokenExchangeResponse.Response.Scope);
        Assert.Equal(grantId, tokenExchangeResponse.Response.GrantId);
    }

    [Fact]
    public async Task TokenExchange_DelegateIdTokenToken_ExpectDelegatedIdToken()
    {
        // Arrange
        var weatherReadScope = await AddWeatherReadScope();
        var weatherClientSecret = CryptographyHelper.GetRandomString(16);
        var weatherClient = await AddWeatherClient(weatherClientSecret);

        var originalClientRegisterResponse = await RegisterEndpointBuilder
            .WithClientName("web-app")
            .WithRedirectUris(["https://webapp.authserver.dk/callback"])
            .WithGrantTypes([GrantTypeConstants.AuthorizationCode])
            .WithScope([weatherReadScope, ScopeConstants.OpenId])
            .WithAccessTokenExpiration(300)
            .Post();

        var impersonatorClientRegisterResponse = await RegisterEndpointBuilder
            .WithClientName("impersonater-api")
            .WithGrantTypes([GrantTypeConstants.TokenExchange, GrantTypeConstants.ClientCredentials])
            .WithScope([weatherReadScope])
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();

        var grantId = await CreateAuthorizationCodeGrant(originalClientRegisterResponse.ClientId, [AuthenticationMethodReferenceConstants.Password]);
        await Consent(UserConstants.SubjectIdentifier, originalClientRegisterResponse.ClientId, [weatherReadScope, ScopeConstants.OpenId], []);

        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(originalClientRegisterResponse.ClientId)
            .WithAuthorizeUser(grantId)
            .WithCodeChallenge(proofKey.CodeChallenge)
            .WithScope([weatherReadScope, ScopeConstants.OpenId])
            .WithResource([weatherClient.ClientUri!])
            .Get();

        var originalClientTokenResponse = await TokenEndpointBuilder
            .WithClientId(originalClientRegisterResponse.ClientId)
            .WithClientSecret(originalClientRegisterResponse.ClientSecret!)
            .WithCode(authorizeResponse.Code!)
            .WithCodeVerifier(proofKey.CodeVerifier)
            .WithResource([weatherClient.ClientUri!])
            .WithGrantType(GrantTypeConstants.AuthorizationCode)
            .Post();

        var impersonatorClientTokenResponse = await TokenEndpointBuilder
            .WithClientId(impersonatorClientRegisterResponse.ClientId)
            .WithClientSecret(impersonatorClientRegisterResponse.ClientSecret!)
            .WithGrantType(GrantTypeConstants.ClientCredentials)
            .WithScope([weatherReadScope])
            .WithResource([weatherClient.ClientUri!])
            .Post();

        // Act
        var tokenExchangeResponse = await TokenEndpointBuilder
            .WithClientId(impersonatorClientRegisterResponse.ClientId)
            .WithClientSecret(impersonatorClientRegisterResponse.ClientSecret!)
            .WithGrantType(GrantTypeConstants.TokenExchange)
            .WithRequestedTokenType(TokenTypeIdentifier.IdToken)
            .WithSubjectToken(originalClientTokenResponse.Response!.AccessToken)
            .WithSubjectTokenType(TokenTypeIdentifier.AccessToken)
            .WithActorToken(impersonatorClientTokenResponse.Response!.AccessToken)
            .WithActorTokenType(TokenTypeIdentifier.AccessToken)
            .Post();

        // Assert
        Assert.NotNull(tokenExchangeResponse);
        Assert.Equal(HttpStatusCode.OK, tokenExchangeResponse.StatusCode);
        Assert.Null(tokenExchangeResponse.Error);
        Assert.NotNull(tokenExchangeResponse.Response);
        Assert.Equal(TokenTypeIdentifier.IdToken, tokenExchangeResponse.Response.IssuedTokenType);
        Assert.NotNull(tokenExchangeResponse.Response.AccessToken);
        Assert.Null(tokenExchangeResponse.Response.IdToken);
        Assert.Null(tokenExchangeResponse.Response.RefreshToken);
        Assert.Equal(TokenTypeSchemaConstants.Bearer, tokenExchangeResponse.Response.TokenType);
        Assert.Equal(3600, tokenExchangeResponse.Response.ExpiresIn);
        Assert.Null(tokenExchangeResponse.Response.Scope);
        Assert.Equal(grantId, tokenExchangeResponse.Response.GrantId);
    }
}