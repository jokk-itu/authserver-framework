using System.Net;
using System.Web;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Tests.Core;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest;
public class AuthorizeIntegrationTest : BaseIntegrationTest
{
    public AuthorizeIntegrationTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
        : base(factory, testOutputHelper)
    {
    }

    [Theory]
    [InlineData("form_post", HttpStatusCode.OK, "http://localhost")]
    [InlineData("query", HttpStatusCode.SeeOther, null)]
    [InlineData("fragment", HttpStatusCode.SeeOther, null)]
    public async Task Authorize_NoPromptWithLoginAndConsentWithRequestObject_ExpectAuthorizationCode(string responseMode, HttpStatusCode statusCode, string? issuer)
    {
        // Arrange
        var identityProvider = await AddIdentityProviderClient();

        var jwks = ClientJwkBuilder.GetClientJwks();
        var registerResponse = await RegisterEndpointBuilder
            .WithRedirectUris(["https://webapp.authserver.dk/"])
            .WithClientName("webapp")
            .WithJwks(jwks.PublicJwks)
            .WithScope([ScopeConstants.UserInfo, ScopeConstants.OpenId])
            .WithRequestObjectSigningAlg(SigningAlg.RsaSha256)
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();

        var grantId = await CreateAuthorizationGrant(registerResponse.ClientId, [AuthenticationMethodReferenceConstants.Password]);
        await Consent(UserConstants.SubjectIdentifier, registerResponse.ClientId, [ScopeConstants.UserInfo, ScopeConstants.OpenId], []);

        // Act
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithRequest(jwks.PrivateJwks)
            .WithAuthorizeUser(grantId)
            .WithScope([ScopeConstants.OpenId, ScopeConstants.UserInfo])
            .WithResource([identityProvider.ClientUri!])
            .WithResponseMode(responseMode)
            .Get();

        // Assert
        Assert.Equal(statusCode, authorizeResponse.StatusCode);
        Assert.Equal(registerResponse.RedirectUris!.Single(), authorizeResponse.LocationUri);
        Assert.Equal(issuer, authorizeResponse.Issuer);
        Assert.NotNull(authorizeResponse.Code);
    }

    [Fact]
    public async Task Authorize_NoPromptWithGrantAndConsent_ExpectRedirectWithAuthorizationCode()
    {
        // Arrange
        var identityProvider = await AddIdentityProviderClient();

        var registerResponse = await RegisterEndpointBuilder
            .WithRedirectUris(["https://webapp.authserver.dk/"])
            .WithClientName("webapp")
            .WithScope([ScopeConstants.OpenId, ScopeConstants.UserInfo])
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();

        var grantId = await CreateAuthorizationGrant(registerResponse.ClientId, [AuthenticationMethodReferenceConstants.Password]);
        await Consent(UserConstants.SubjectIdentifier, registerResponse.ClientId, [ScopeConstants.OpenId, ScopeConstants.UserInfo], []);

        // Act
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithAuthorizeUser(grantId)
            .WithScope([ScopeConstants.UserInfo, ScopeConstants.OpenId])
            .WithResource([identityProvider.ClientUri!])
            .Get();

        // Assert
        Assert.Equal(HttpStatusCode.SeeOther, authorizeResponse.StatusCode);
        Assert.Equal(registerResponse.RedirectUris!.Single(), authorizeResponse.LocationUri);
        Assert.NotNull(authorizeResponse.Code);
    }

    [Fact]
    public async Task Authorize_NoPromptWithIdTokenHintWithMaxAgeZero_ExpectRedirectLogin()
    {
        // Arrange
        var identityProvider = await AddIdentityProviderClient();

        var registerResponse = await RegisterEndpointBuilder
            .WithRedirectUris(["https://webapp.authserver.dk/"])
            .WithScope([ScopeConstants.OpenId, ScopeConstants.UserInfo])
            .WithClientName("webapp")
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();

        await CreateAuthorizationGrant(registerResponse.ClientId, [AuthenticationMethodReferenceConstants.Password]);

        var databaseContext = ServiceProvider.GetRequiredService<AuthorizationDbContext>();
        var grant = await databaseContext
            .Set<AuthorizationGrant>()
            .Where(x => x.Client.Id == registerResponse.ClientId)
            .Include(x => x.Session)
            .SingleAsync();

        var idToken = this.JwtBuilder.GetIdToken(
            registerResponse.ClientId,
            grant.Id,
            UserConstants.SubjectIdentifier,
            grant.Session.Id,
            [AuthenticationMethodReferenceConstants.Password],
            LevelOfAssuranceLow);

        // Act
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithMaxAge(0)
            .WithScope([ScopeConstants.OpenId, ScopeConstants.UserInfo])
            .WithResource([identityProvider.ClientUri!])
            .WithIdTokenHint(idToken)
            .Get();

        // Assert
        Assert.Equal(HttpStatusCode.SeeOther, authorizeResponse.StatusCode);
        Assert.Equal(UserInteraction.LoginUri, authorizeResponse.LocationUri);

        var originalRequestTrimmed = new Uri(authorizeResponse.RequestUri!).GetLeftPart(UriPartial.Path);
        var returnUrlRequest = new Uri(authorizeResponse.ReturnUrl!);
        Assert.Equal(originalRequestTrimmed, returnUrlRequest.GetLeftPart(UriPartial.Path));

        var returnUrlQuery = HttpUtility.ParseQueryString(returnUrlRequest.Query);
        Assert.Equal(registerResponse.ClientId, returnUrlQuery.Get(Parameter.ClientId));

        var requestUri = returnUrlQuery.Get(Parameter.ClientId);
        Assert.NotNull(requestUri);

        var reference = requestUri[RequestUriConstants.RequestUriPrefix.Length..];
        Assert.NotNull(reference);
    }

    [Fact]
    public async Task Authorize_NoPromptWithPreviousLoginAndNoConsent_ExpectRedirectConsent()
    {
        // Arrange
        var identityProvider = await AddIdentityProviderClient();

        var registerResponse = await RegisterEndpointBuilder
            .WithRedirectUris(["https://webapp.authserver.dk/"])
            .WithClientName("webapp")
            .WithScope([ScopeConstants.OpenId, ScopeConstants.UserInfo])
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();

        var grantId = await CreateAuthorizationGrant(registerResponse.ClientId, [AuthenticationMethodReferenceConstants.Password]);

        // Act
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithScope([ScopeConstants.OpenId, ScopeConstants.UserInfo])
            .WithResource([identityProvider.ClientUri!])
            .WithAuthorizeUser(grantId)
            .Get();

        // Assert
        Assert.Equal(HttpStatusCode.SeeOther, authorizeResponse.StatusCode);
        Assert.Equal(UserInteraction.ConsentUri, authorizeResponse.LocationUri);

        var originalRequestTrimmed = new Uri(authorizeResponse.RequestUri!).GetLeftPart(UriPartial.Path);
        var returnUrlRequest = new Uri(authorizeResponse.ReturnUrl!);
        Assert.Equal(originalRequestTrimmed, returnUrlRequest.GetLeftPart(UriPartial.Path));

        var returnUrlQuery = HttpUtility.ParseQueryString(returnUrlRequest.Query);
        Assert.Equal(registerResponse.ClientId, returnUrlQuery.Get(Parameter.ClientId));

        var requestUri = returnUrlQuery.Get(Parameter.ClientId);
        Assert.NotNull(requestUri);

        var reference = requestUri[RequestUriConstants.RequestUriPrefix.Length..];
        Assert.NotNull(reference);
    }

    [Fact]
    public async Task Authorize_NoPromptWithMultipleActiveUsers_ExpectRedirectSelectAccount()
    {
        // Arrange
        var identityProvider = await AddIdentityProviderClient();

        var registerResponse = await RegisterEndpointBuilder
            .WithRedirectUris(["https://webapp.authserver.dk/"])
            .WithClientName("webapp")
            .WithScope([ScopeConstants.OpenId, ScopeConstants.UserInfo])
            .Post();

        // Act
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithScope([ScopeConstants.OpenId, ScopeConstants.UserInfo])
            .WithResource([identityProvider.ClientUri!])
            .Get();

        // Assert
        Assert.Equal(HttpStatusCode.SeeOther, authorizeResponse.StatusCode);
        Assert.Equal(UserInteraction.AccountSelectionUri, authorizeResponse.LocationUri);

        var originalRequestTrimmed = new Uri(authorizeResponse.RequestUri!).GetLeftPart(UriPartial.Path);
        var returnUrlRequest = new Uri(authorizeResponse.ReturnUrl!);
        Assert.Equal(originalRequestTrimmed, returnUrlRequest.GetLeftPart(UriPartial.Path));

        var returnUrlQuery = HttpUtility.ParseQueryString(returnUrlRequest.Query);
        Assert.Equal(registerResponse.ClientId, returnUrlQuery.Get(Parameter.ClientId));

        var requestUri = returnUrlQuery.Get(Parameter.ClientId);
        Assert.NotNull(requestUri);

        var reference = requestUri[RequestUriConstants.RequestUriPrefix.Length..];
        Assert.NotNull(reference);
    }

    [Fact]
    public async Task Authorize_InvalidClientId_ExpectBadRequest()
    {
        // Act
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId("invalid_client_id")
            .Get();

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, authorizeResponse.StatusCode);
        Assert.Equal(ErrorCode.InvalidClient, authorizeResponse.Error);
        Assert.NotNull(authorizeResponse.ErrorDescription);
    }

    [Fact]
    public async Task Authorize_InvalidScope_ExpectRedirectInvalidScope()
    {
        // Arrange
        var registerResponse = await RegisterEndpointBuilder
            .WithRedirectUris(["https://webapp.authserver.dk/"])
            .WithClientName("webapp")
            .Post();

        // Act
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithScope(["invalid_scope"])
            .Post();

        // Assert
        Assert.Equal(HttpStatusCode.SeeOther, authorizeResponse.StatusCode);
        Assert.Equal(registerResponse.RedirectUris!.Single(), authorizeResponse.LocationUri);
        Assert.Equal(ErrorCode.InvalidScope, authorizeResponse.Error);
        Assert.NotNull(authorizeResponse.ErrorDescription);
    }
}
