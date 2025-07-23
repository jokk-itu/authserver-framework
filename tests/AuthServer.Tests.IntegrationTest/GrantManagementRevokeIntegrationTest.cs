using AuthServer.Constants;
using AuthServer.Tests.Core;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
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
        Assert.Single(grantResponse.WwwAuthenticate, x => x.Scheme == TokenTypeSchemaConstants.Bearer);
        Assert.Single(grantResponse.WwwAuthenticate, x => x.Scheme == TokenTypeSchemaConstants.DPoP);
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

        var grantId = await CreateAuthorizationCodeGrant(registerResponse.ClientId, [AuthenticationMethodReferenceConstants.Password]);
        await Consent(UserConstants.SubjectIdentifier, registerResponse.ClientId, [ScopeConstants.UserInfo, ScopeConstants.OpenId], []);

        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithAuthorizeUser(grantId)
            .WithCodeChallenge(proofKey.CodeChallenge)
            .WithScope([ScopeConstants.UserInfo, ScopeConstants.OpenId])
            .WithResource([identityProviderClient.ClientUri!])
            .Get();

        var tokenResponse = await TokenEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithCode(authorizeResponse.Code!)
            .WithCodeVerifier(proofKey.CodeVerifier)
            .WithResource([identityProviderClient.ClientUri!])
            .WithGrantType(GrantTypeConstants.AuthorizationCode)
            .Post();

        // Act
        var grantResponse = await GrantManagementEndpointBuilder
            .WithGrantId(tokenResponse.Response!.GrantId!)
            .WithToken(tokenResponse.Response!.AccessToken)
            .Delete();

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, grantResponse.StatusCode);
        Assert.Single(grantResponse.WwwAuthenticate, x => x.Scheme == TokenTypeSchemaConstants.Bearer);
        Assert.Single(grantResponse.WwwAuthenticate, x => x.Scheme == TokenTypeSchemaConstants.DPoP);
    }

    [Fact]
    public async Task Revoke_InvalidGrantId_ExpectNotFound()
    {
        var identityProviderClient = await AddIdentityProviderClient();

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("web-app")
            .WithRedirectUris(["https://webapp.authserver.dk/callback"])
            .WithScope([ScopeConstants.GrantManagementRevoke, ScopeConstants.OpenId])
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();

        var grantId = await CreateAuthorizationCodeGrant(registerResponse.ClientId, [AuthenticationMethodReferenceConstants.Password]);
        await Consent(UserConstants.SubjectIdentifier, registerResponse.ClientId, [ScopeConstants.GrantManagementRevoke, ScopeConstants.OpenId], []);

        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithAuthorizeUser(grantId)
            .WithCodeChallenge(proofKey.CodeChallenge)
            .WithScope([ScopeConstants.GrantManagementRevoke, ScopeConstants.OpenId])
            .WithResource([identityProviderClient.ClientUri!])
            .Get();

        var tokenResponse = await TokenEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithCode(authorizeResponse.Code!)
            .WithCodeVerifier(proofKey.CodeVerifier)
            .WithResource([identityProviderClient.ClientUri!])
            .WithGrantType(GrantTypeConstants.AuthorizationCode)
            .Post();

        // Act
        var grantResponse = await GrantManagementEndpointBuilder
            .WithGrantId("invalid_grant_id")
            .WithToken(tokenResponse.Response!.AccessToken)
            .Delete();

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, grantResponse.StatusCode);
    }

    [Fact]
    public async Task Revoke_ClientDoesNotOwnGrant_ExpectForbidden()
    {
        var identityProviderClient = await AddIdentityProviderClient();

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("web-app")
            .WithRedirectUris(["https://webapp.authserver.dk/callback"])
            .WithScope([ScopeConstants.GrantManagementRevoke, ScopeConstants.OpenId])
            .Post();

        var otherRegisterResponse = await RegisterEndpointBuilder
            .WithClientName("other-web-app")
            .WithRedirectUris(["https://other-webapp.authserver.dk/callback"])
            .WithScope([ScopeConstants.GrantManagementRevoke, ScopeConstants.OpenId])
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();

        var otherGrantId = await CreateAuthorizationCodeGrant(otherRegisterResponse.ClientId, [AuthenticationMethodReferenceConstants.Password]);
        var grantId = await CreateAuthorizationCodeGrant(registerResponse.ClientId, [AuthenticationMethodReferenceConstants.Password]);
        await Consent(UserConstants.SubjectIdentifier, registerResponse.ClientId, [ScopeConstants.GrantManagementRevoke, ScopeConstants.OpenId], []);

        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithAuthorizeUser(grantId)
            .WithCodeChallenge(proofKey.CodeChallenge)
            .WithScope([ScopeConstants.GrantManagementRevoke, ScopeConstants.OpenId])
            .WithResource([identityProviderClient.ClientUri!])
            .Get();

        var tokenResponse = await TokenEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithCode(authorizeResponse.Code!)
            .WithCodeVerifier(proofKey.CodeVerifier)
            .WithResource([identityProviderClient.ClientUri!])
            .WithGrantType(GrantTypeConstants.AuthorizationCode)
            .Post();

        // Act
        var grantResponse = await GrantManagementEndpointBuilder
            .WithGrantId(otherGrantId)
            .WithToken(tokenResponse.Response!.AccessToken)
            .Delete();

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, grantResponse.StatusCode);
        Assert.Single(grantResponse.WwwAuthenticate, x => x.Scheme == TokenTypeSchemaConstants.Bearer);
        Assert.Single(grantResponse.WwwAuthenticate, x => x.Scheme == TokenTypeSchemaConstants.DPoP);
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

        var grantId = await CreateAuthorizationCodeGrant(registerResponse.ClientId, [AuthenticationMethodReferenceConstants.Password]);
        await Consent(UserConstants.SubjectIdentifier, registerResponse.ClientId, [ScopeConstants.GrantManagementRevoke, ScopeConstants.OpenId], []);

        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithAuthorizeUser(grantId)
            .WithCodeChallenge(proofKey.CodeChallenge)
            .WithScope([ScopeConstants.GrantManagementRevoke, ScopeConstants.OpenId])
            .WithResource([identityProviderClient.ClientUri!])
            .Get();

        var tokenResponse = await TokenEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithCode(authorizeResponse.Code!)
            .WithCodeVerifier(proofKey.CodeVerifier)
            .WithResource([identityProviderClient.ClientUri!])
            .WithGrantType(GrantTypeConstants.AuthorizationCode)
            .Post();

        // Act
        var grantResponse = await GrantManagementEndpointBuilder
            .WithGrantId(tokenResponse.Response!.GrantId!)
            .WithToken(tokenResponse.Response!.AccessToken)
            .Delete();

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, grantResponse.StatusCode);
    }
}