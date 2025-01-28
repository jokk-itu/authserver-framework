using System.Net;
using System.Web;
using AuthServer.Authorize.Abstractions;
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

    [Fact]
    public async Task Authorize_NoPromptWithLoginAndConsentWithRequestObject_ExpectRedirectWithAuthorizationCode()
    {
        // Arrange
        var jwks = ClientJwkBuilder.GetClientJwks();
        var registerResponse = await RegisterEndpointBuilder
            .WithRedirectUris(["https://webapp.authserver.dk/"])
            .WithClientName("webapp")
            .WithJwks(jwks.PublicJwks)
            .WithRequestObjectSigningAlg(SigningAlg.RsaSha256)
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
            [ScopeConstants.OpenId],
            [],
            CancellationToken.None);

        // Act
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithRequest(jwks.PrivateJwks)
            .WithAuthorizeUser(Guid.NewGuid().ToString())
            .Get();

        // Assert
        Assert.Equal(HttpStatusCode.SeeOther, authorizeResponse.StatusCode);
        Assert.Equal(registerResponse.RedirectUris!.Single(), authorizeResponse.LocationUri);
        Assert.NotNull(authorizeResponse.Code);
    }

    [Fact]
    public async Task Authorize_NoPromptWithGrantAndConsent_ExpectRedirectWithAuthorizationCode()
    {
        // Arrange
        var registerResponse = await RegisterEndpointBuilder
            .WithRedirectUris(["https://webapp.authserver.dk/"])
            .WithClientName("webapp")
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
            [ScopeConstants.OpenId],
            [],
            CancellationToken.None);

        // Act
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithAuthorizeUser(Guid.NewGuid().ToString())
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
        var registerResponse = await RegisterEndpointBuilder
            .WithRedirectUris(["https://webapp.authserver.dk/"])
            .WithClientName("webapp")
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();

        var authorizeService = ServiceProvider.GetRequiredService<IAuthorizeService>();
        await authorizeService.CreateAuthorizationGrant(
            UserConstants.SubjectIdentifier,
            registerResponse.ClientId,
            [AuthenticationMethodReferenceConstants.Password],
            CancellationToken.None);

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
        var registerResponse = await RegisterEndpointBuilder
            .WithRedirectUris(["https://webapp.authserver.dk/"])
            .WithClientName("webapp")
            .Post();

        await AddUser();
        await AddAuthenticationContextReferences();

        var authorizeService = ServiceProvider.GetRequiredService<IAuthorizeService>();
        await authorizeService.CreateAuthorizationGrant(
            UserConstants.SubjectIdentifier,
            registerResponse.ClientId,
            [AuthenticationMethodReferenceConstants.Password],
            CancellationToken.None);

        // Act
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithAuthorizeUser(Guid.NewGuid().ToString())
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
        var registerResponse = await RegisterEndpointBuilder
            .WithRedirectUris(["https://webapp.authserver.dk/"])
            .WithClientName("webapp")
            .Post();

        // Act
        var authorizeResponse = await AuthorizeEndpointBuilder
            .WithClientId(registerResponse.ClientId)
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
            .Get();

        // Assert
        Assert.Equal(HttpStatusCode.SeeOther, authorizeResponse.StatusCode);
        Assert.Equal(registerResponse.RedirectUris!.Single(), authorizeResponse.LocationUri);
        Assert.Equal(ErrorCode.InvalidScope, authorizeResponse.Error);
        Assert.NotNull(authorizeResponse.ErrorDescription);
    }
}
