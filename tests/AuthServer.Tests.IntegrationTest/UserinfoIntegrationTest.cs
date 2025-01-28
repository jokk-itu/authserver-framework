using System.Net;
using System.Text.Json;
using AuthServer.Authorize.Abstractions;
using AuthServer.Constants;
using AuthServer.Enums;
using AuthServer.Extensions;
using AuthServer.Tests.Core;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest;

public class UserinfoIntegrationTest : BaseIntegrationTest
{
    public UserinfoIntegrationTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
        : base(factory, testOutputHelper)
    {
    }

    [Fact]
    public async Task Userinfo_PostWithoutAccessToken_ExpectUnauthorizedWithInvalidRequest()
    {
        // Arrange and Act
        var userinfoResponse = await UserinfoEndpointBuilder.Post();
        
        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, userinfoResponse.StatusCode);
        Assert.Single(userinfoResponse.WwwAuthenticate);
        var wwwAuthenticate = userinfoResponse.WwwAuthenticate.Single();
        Assert.Equal("Bearer", wwwAuthenticate.Scheme);
        Assert.Equal("error=\"invalid_request\"", wwwAuthenticate.Parameter);
    }

    [Fact]
    public async Task Userinfo_PostWithAccessTokenWithoutUserinfoScope_ExpectForbidden()
    {
        // Arrange
        var grantManagementQueryScope = GetGrantManagementQueryScope();
        var identityProviderClient = await AddIdentityProviderClient();

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("web-app")
            .WithRedirectUris(["https://webapp.authserver.dk/callback"])
            .WithGrantTypes([GrantTypeConstants.AuthorizationCode])
            .WithScope([grantManagementQueryScope, ScopeConstants.OpenId])
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();

        var authorizeService = ServiceProvider.GetRequiredService<IAuthorizeService>();
        await authorizeService.CreateAuthorizationGrant(
            UserConstants.SubjectIdentifier,
            registerResponse.ClientId,
            [AuthenticationMethodReferenceConstants.Password],
            CancellationToken.None);

        await authorizeService.CreateOrUpdateConsentGrant(
            UserConstants.SubjectIdentifier,
            registerResponse.ClientId,
            [grantManagementQueryScope, ScopeConstants.OpenId],
            [],
            CancellationToken.None);

        var proofKeyForCodeExchange = ProofKeyForCodeExchangeHelper.GetProofKeyForCodeExchange();
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithAuthorizeUser(Guid.NewGuid().ToString())
            .WithCodeChallenge(proofKeyForCodeExchange.CodeChallenge)
            .WithScope([grantManagementQueryScope, ScopeConstants.OpenId])
            .Get();

        var tokenResponse = await TokenEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithCode(authorizeResponse.Code!)
            .WithCodeVerifier(proofKeyForCodeExchange.CodeVerifier)
            .WithResource([identityProviderClient.ClientUri!])
            .WithGrantType(GrantTypeConstants.AuthorizationCode)
            .Post();

        // Act
        var userinfoResponse = await UserinfoEndpointBuilder
            .WithAccessToken(tokenResponse.AccessToken)
            .Post();

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, userinfoResponse.StatusCode);
        Assert.Single(userinfoResponse.WwwAuthenticate);
        var wwwAuthenticate = userinfoResponse.WwwAuthenticate.Single();
        Assert.Equal("Bearer", wwwAuthenticate.Scheme);
        Assert.Equal("error=\"insufficient_scope\"", wwwAuthenticate.Parameter);
    }

    [Fact]
    public async Task Userinfo_Post_ExpectJson()
    {
        // Arrange
        var userinfoScope = GetUserinfoScope();
        var identityProviderClient = await AddIdentityProviderClient();

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("web-app")
            .WithRedirectUris(["https://webapp.authserver.dk/callback"])
            .WithGrantTypes([GrantTypeConstants.AuthorizationCode])
            .WithScope([userinfoScope, ScopeConstants.OpenId])
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();

        var authorizeService = ServiceProvider.GetRequiredService<IAuthorizeService>();
        await authorizeService.CreateAuthorizationGrant(
            UserConstants.SubjectIdentifier,
            registerResponse.ClientId,
            [AuthenticationMethodReferenceConstants.Password],
            CancellationToken.None);

        await authorizeService.CreateOrUpdateConsentGrant(
            UserConstants.SubjectIdentifier,
            registerResponse.ClientId,
            [userinfoScope, ScopeConstants.OpenId],
            [],
            CancellationToken.None);

        var proofKeyForCodeExchange = ProofKeyForCodeExchangeHelper.GetProofKeyForCodeExchange();
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithAuthorizeUser(Guid.NewGuid().ToString())
            .WithCodeChallenge(proofKeyForCodeExchange.CodeChallenge)
            .WithScope([userinfoScope, ScopeConstants.OpenId])
            .Get();

        var tokenResponse = await TokenEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithCode(authorizeResponse.Code!)
            .WithCodeVerifier(proofKeyForCodeExchange.CodeVerifier)
            .WithResource([identityProviderClient.ClientUri!])
            .WithGrantType(GrantTypeConstants.AuthorizationCode)
            .Post();

        // Act
        var userinfoResponse = await UserinfoEndpointBuilder
            .WithAccessToken(tokenResponse.AccessToken)
            .Post();

        // Assert
        Assert.Equal(HttpStatusCode.OK, userinfoResponse.StatusCode);
        Assert.Equal(MimeTypeConstants.Json, userinfoResponse.ContentType!.MediaType);
        var claims = JsonSerializer.Deserialize<Dictionary<string, object>>(userinfoResponse.Content!);
        Assert.NotNull(claims);
        Assert.Equal(UserConstants.SubjectIdentifier, claims[ClaimNameConstants.Sub].ToString());
    }

    [Fact]
    public async Task Userinfo_Get_ExpectJwt()
    {
        // Arrange
        var userinfoScope = GetUserinfoScope();
        var identityProviderClient = await AddIdentityProviderClient();
        var jwks = ClientJwkBuilder.GetClientJwks();

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("web-app")
            .WithRedirectUris(["https://webapp.authserver.dk/callback"])
            .WithGrantTypes([GrantTypeConstants.AuthorizationCode])
            .WithScope([userinfoScope, ScopeConstants.OpenId])
            .WithUserinfoSignedResponseAlg(SigningAlg.RsaSha256)
            .WithJwks(jwks.PublicJwks)
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();

        var authorizeService = ServiceProvider.GetRequiredService<IAuthorizeService>();
        await authorizeService.CreateAuthorizationGrant(
            UserConstants.SubjectIdentifier,
            registerResponse.ClientId,
            [AuthenticationMethodReferenceConstants.Password],
            CancellationToken.None);

        await authorizeService.CreateOrUpdateConsentGrant(
            UserConstants.SubjectIdentifier,
            registerResponse.ClientId,
            [userinfoScope, ScopeConstants.OpenId],
            [],
            CancellationToken.None);

        var proofKeyForCodeExchange = ProofKeyForCodeExchangeHelper.GetProofKeyForCodeExchange();
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithAuthorizeUser(Guid.NewGuid().ToString())
            .WithCodeChallenge(proofKeyForCodeExchange.CodeChallenge)
            .WithScope([userinfoScope, ScopeConstants.OpenId])
            .Get();

        var tokenResponse = await TokenEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithCode(authorizeResponse.Code!)
            .WithCodeVerifier(proofKeyForCodeExchange.CodeVerifier)
            .WithResource([identityProviderClient.ClientUri!])
            .WithGrantType(GrantTypeConstants.AuthorizationCode)
            .Post();

        // Act
        var userinfoResponse = await UserinfoEndpointBuilder
            .WithAccessToken(tokenResponse.AccessToken)
            .Post();

        // Assert
        Assert.Equal(HttpStatusCode.OK, userinfoResponse.StatusCode);
        Assert.Equal(MimeTypeConstants.Jwt, userinfoResponse.ContentType!.MediaType);
        
        var jsonWebTokenHandler = new JsonWebTokenHandler();
        var tokenValidationParameters = new TokenValidationParameters
        {
            IssuerSigningKey = JwksDocument.GetSigningKey(SigningAlg.RsaSha256),
            ValidIssuer = DiscoveryDocument.Issuer,
            ValidAudience = registerResponse.ClientId,
            ValidTypes = [TokenTypeHeaderConstants.UserinfoToken],
            ValidAlgorithms = [SigningAlg.RsaSha256.GetDescription()]
        };
        var validatedToken = await jsonWebTokenHandler.ValidateTokenAsync(userinfoResponse.Content, tokenValidationParameters);

        Assert.Equal(UserConstants.SubjectIdentifier, validatedToken.Claims[ClaimNameConstants.Sub].ToString());
    }
}