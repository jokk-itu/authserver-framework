using AuthServer.Tests.Core;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net;
using AuthServer.Constants;
using AuthServer.Helpers;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest;

public class EndSessionIntegrationTest : BaseIntegrationTest
{
    public EndSessionIntegrationTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
        : base(factory, testOutputHelper)
    {
    }

    [Fact]
    public async Task EndSession_LogoutAtIdentityProvider_ExpectOk()
    {
        // Arrange
        var registerResponse = await RegisterEndpointBuilder
            .WithRedirectUris(["https://webapp.authserver.dk/"])
            .WithClientName("webapp")
            .Post();

        await AddAuthenticationContextReferences();
        await AddUser();
        await CreateAuthorizationCodeGrant(
            registerResponse.ClientId,
            [AuthenticationMethodReferenceConstants.Password]);

        // Act
        var endSessionResponse = await EndSessionEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithEndSessionUser(UserConstants.SubjectIdentifier, true)
            .Get();

       // Assert
       Assert.Equal(HttpStatusCode.OK, endSessionResponse.StatusCode);
    }

    [Fact]
    public async Task EndSession_WithPostLogoutRedirectUri_ExpectSeeOther()
    {
        // Arrange
        const string postLogoutRedirectUri = "https://webapp.authserver.dk/logged-out";
        var registerResponse = await RegisterEndpointBuilder
            .WithRedirectUris(["https://webapp.authserver.dk/"])
            .WithClientName("webapp")
            .WithPostLogoutRedirectUris([postLogoutRedirectUri])
            .Post();

        await AddAuthenticationContextReferences();
        await AddUser();
        await CreateAuthorizationCodeGrant(
            registerResponse.ClientId,
            [AuthenticationMethodReferenceConstants.Password]);

        // Act
        var state = CryptographyHelper.GetRandomString(16);
        var endSessionResponse = await EndSessionEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithPostLogoutRedirectUri(postLogoutRedirectUri)
            .WithState(state)
            .WithEndSessionUser(UserConstants.SubjectIdentifier, false)
            .Get();

        // Assert
        Assert.Equal(HttpStatusCode.SeeOther, endSessionResponse.StatusCode);
        Assert.Equal(postLogoutRedirectUri, endSessionResponse.LocationUri);
        Assert.Equal(state, endSessionResponse.State);
    }

    [Fact]
    public async Task EndSession_InteractionRequired_ExpectSeeOther()
    {
        // Act
        var endSessionResponse = await EndSessionEndpointBuilder.Get();

        // Assert
        Assert.Equal(HttpStatusCode.SeeOther, endSessionResponse.StatusCode);
        Assert.Equal(UserInteraction.EndSessionUri, endSessionResponse.LocationUri);
    }

    [Fact]
    public async Task EndSession_PostLogoutRedirectUriWithoutState_ExpectBadRequest()
    {
        // Act
        var endSessionResponse = await EndSessionEndpointBuilder
            .WithPostLogoutRedirectUri("https://webapp.authserver.dk/logged-out")
            .Post();

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, endSessionResponse.StatusCode);
    }
}