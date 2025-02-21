using System.Net;
using AuthServer.Constants;
using AuthServer.Tests.Core;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest;

public class GrantManagementRevokeIntegrationTest : BaseIntegrationTest
{
    public GrantManagementRevokeIntegrationTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
        : base(factory, testOutputHelper)
    {
    }

    [Fact]
    public async Task Revoke_WithoutAccessToken_ExpectUnauthorizedWithInvalidRequest()
    {
        // Arrange and Act
        var grantResponse = await GrantManagementEndpointBuilder
            .WithGrantId("random")
            .Delete();

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, grantResponse.StatusCode);
        Assert.Single(grantResponse.WwwAuthenticate);
        var wwwAuthenticate = grantResponse.WwwAuthenticate.Single();
        Assert.Equal("Bearer", wwwAuthenticate.Scheme);
        Assert.Equal("error=\"invalid_request\"", wwwAuthenticate.Parameter);
    }

    [Fact]
    public async Task Revoke_WithoutGrantManagementRevokeScope_ExpectForbidden()
    {
        // Arrange
        var identityProviderClient = await AddIdentityProviderClient();

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("web-app")
            .WithRedirectUris(["https://webapp.authserver.dk/callback"])
            .WithScope([ScopeConstants.UserInfo, ScopeConstants.OpenId])
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();

        var grantId = await CreateAuthorizationGrant(registerResponse.ClientId, [AuthenticationMethodReferenceConstants.Password]);
        await Consent(UserConstants.SubjectIdentifier, registerResponse.ClientId, [ScopeConstants.UserInfo, ScopeConstants.OpenId], []);

        var proofKeyForCodeExchange = ProofKeyForCodeExchangeHelper.GetProofKeyForCodeExchange();
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithAuthorizeUser(grantId)
            .WithCodeChallenge(proofKeyForCodeExchange.CodeChallenge)
            .WithScope([ScopeConstants.UserInfo, ScopeConstants.OpenId])
            .WithResource([identityProviderClient.ClientUri!])
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
        var grantResponse = await GrantManagementEndpointBuilder
            .WithGrantId(tokenResponse.GrantId!)
            .WithToken(tokenResponse.AccessToken)
            .Delete();

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, grantResponse.StatusCode);
        Assert.Single(grantResponse.WwwAuthenticate);
        var wwwAuthenticate = grantResponse.WwwAuthenticate.Single();
        Assert.Equal("Bearer", wwwAuthenticate.Scheme);
        Assert.Equal("error=\"insufficient_scope\"", wwwAuthenticate.Parameter);
    }

    [Fact]
    public async Task Revoke_ActiveGrant_ExpectRevokedGrant()
    {
        // Arrange
        var identityProviderClient = await AddIdentityProviderClient();

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("web-app")
            .WithRedirectUris(["https://webapp.authserver.dk/callback"])
            .WithScope([ScopeConstants.GrantManagementRevoke, ScopeConstants.OpenId])
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();

        var grantId = await CreateAuthorizationGrant(registerResponse.ClientId, [AuthenticationMethodReferenceConstants.Password]);
        await Consent(UserConstants.SubjectIdentifier, registerResponse.ClientId, [ScopeConstants.GrantManagementRevoke, ScopeConstants.OpenId], []);

        var proofKeyForCodeExchange = ProofKeyForCodeExchangeHelper.GetProofKeyForCodeExchange();
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithAuthorizeUser(grantId)
            .WithCodeChallenge(proofKeyForCodeExchange.CodeChallenge)
            .WithScope([ScopeConstants.GrantManagementRevoke, ScopeConstants.OpenId])
            .WithResource([identityProviderClient.ClientUri!])
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
        var grantResponse = await GrantManagementEndpointBuilder
            .WithGrantId(tokenResponse.GrantId!)
            .WithToken(tokenResponse.AccessToken)
            .Delete();

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, grantResponse.StatusCode);
    }
}