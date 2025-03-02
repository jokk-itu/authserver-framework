using AuthServer.Constants;
using AuthServer.Endpoints.Responses;
using AuthServer.Tests.Core;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using System.Text.Json;
using AuthServer.Core;
using AuthServer.Entities;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest;

public class GrantManagementQueryIntegrationTest : BaseIntegrationTest
{
    public GrantManagementQueryIntegrationTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
        : base(factory, testOutputHelper)
    {
    }

    [Fact]
    public async Task Query_WithoutAccessToken_ExpectUnauthorizedWithInvalidRequest()
    {
        // Arrange and Act
        var grantResponse = await GrantManagementEndpointBuilder
            .WithGrantId("random")
            .Get();

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, grantResponse.StatusCode);
        Assert.Single(grantResponse.WwwAuthenticate);
        var wwwAuthenticate = grantResponse.WwwAuthenticate.Single();
        Assert.Equal("Bearer", wwwAuthenticate.Scheme);
        Assert.Equal("error=\"invalid_request\"", wwwAuthenticate.Parameter);
    }

    [Fact]
    public async Task Query_WithoutGrantManagementQueryScope_ExpectForbidden()
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
            .Get();

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, grantResponse.StatusCode);
        Assert.Single(grantResponse.WwwAuthenticate);
        var wwwAuthenticate = grantResponse.WwwAuthenticate.Single();
        Assert.Equal("Bearer", wwwAuthenticate.Scheme);
        Assert.Equal("error=\"insufficient_scope\"", wwwAuthenticate.Parameter);
    }

    [Fact]
    public async Task Query_GrantWithConsent_ExpectGrant()
    {
        // Arrange
        var identityProviderClient = await AddIdentityProviderClient();

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("web-app")
            .WithRedirectUris(["https://webapp.authserver.dk/callback"])
            .WithScope([ScopeConstants.GrantManagementQuery, ScopeConstants.OpenId, ScopeConstants.Profile])
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();

        var grantId = await CreateAuthorizationGrant(registerResponse.ClientId, [AuthenticationMethodReferenceConstants.Password]);
        await Consent(UserConstants.SubjectIdentifier, registerResponse.ClientId, [ScopeConstants.GrantManagementQuery, ScopeConstants.OpenId, ScopeConstants.Profile], [ClaimNameConstants.Name]);

        var proofKeyForCodeExchange = ProofKeyForCodeExchangeHelper.GetProofKeyForCodeExchange();
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithAuthorizeUser(grantId)
            .WithCodeChallenge(proofKeyForCodeExchange.CodeChallenge)
            .WithScope([ScopeConstants.GrantManagementQuery, ScopeConstants.OpenId, ScopeConstants.Profile])
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
            .Get();

        // Assert
        Assert.Equal(HttpStatusCode.OK, grantResponse.StatusCode);

        var getGrantResponse = JsonSerializer.Deserialize<GetGrantResponse>(grantResponse.Content!);
        Assert.NotNull(getGrantResponse);

        var grant = (await ServiceProvider.GetRequiredService<AuthorizationDbContext>().FindAsync<AuthorizationGrant>([grantId], CancellationToken.None))!;
        Assert.Equal(grant.CreatedAuthTime, getGrantResponse.CreatedAt);
        Assert.Equal(grant.UpdatedAuthTime, getGrantResponse.UpdatedAt);

        Assert.Single(getGrantResponse.Claims);
        Assert.Equal(ClaimNameConstants.Name, getGrantResponse.Claims.Single());

        Assert.Single(getGrantResponse.Scopes);

        var scopeDto = getGrantResponse.Scopes.Single();
        Assert.Single(scopeDto.Resources);
        Assert.Equal(DiscoveryDocument.Issuer, scopeDto.Resources.Single());

        var expectedScopes = new List<string> { ScopeConstants.GrantManagementQuery, ScopeConstants.Profile, ScopeConstants.OpenId };
        Assert.Equivalent(expectedScopes, scopeDto.Scopes, strict: true);
    }
}