using System.Net;
using System.Web;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Repositories.Abstractions;
using AuthServer.Tests.Core;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest;

public class PushedAuthorizationIntegrationTest : BaseIntegrationTest
{
    public PushedAuthorizationIntegrationTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
        : base(factory, testOutputHelper)
    {
    }

    [Fact]
    public async Task PushedAuthorization_ValidRequest_ExpectCreated()
    {
        // Arrange
        var identityClient = await AddIdentityProviderClient();

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("web-app")
            .WithRedirectUris(["https://webapp.authserver.dk/callback"])
            .WithGrantTypes([GrantTypeConstants.AuthorizationCode])
            .WithScope([ScopeConstants.UserInfo, ScopeConstants.OpenId])
            .WithRequestUriExpiration(300)
            .Post();

        // Act
        var pushedAuthorizationResponse = await PushedAuthorizationEndpointBuilder
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.ClientSecretBasic)
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithScope([ScopeConstants.OpenId, ScopeConstants.UserInfo])
            .WithResource([identityClient.ClientUri!])
            .Post();

        // Assert
        Assert.Equal(HttpStatusCode.Created, pushedAuthorizationResponse.StatusCode);
        Assert.Null(pushedAuthorizationResponse.Error);
        Assert.NotNull(pushedAuthorizationResponse.Response);
        Assert.NotNull(pushedAuthorizationResponse.Location);
        Assert.Equal(EndpointResolver.AuthorizationEndpoint, pushedAuthorizationResponse.Location.GetLeftPart(UriPartial.Path));
        Assert.Equal(registerResponse.RequestUriExpiration, pushedAuthorizationResponse.Response.ExpiresIn);

        var authorizeRequestQuery = HttpUtility.ParseQueryString(pushedAuthorizationResponse.Location.Query);
        var clientId = authorizeRequestQuery.Get(Parameter.ClientId);
        var requestUri = authorizeRequestQuery.Get(Parameter.RequestUri);
        Assert.Equal(registerResponse.ClientId, clientId);
        Assert.Equal(pushedAuthorizationResponse.Response.RequestUri, requestUri);

        var reference = pushedAuthorizationResponse.Response.RequestUri[RequestUriConstants.RequestUriPrefix.Length..];
        Assert.NotEmpty(reference);

        Assert.Single(ServiceProvider
            .GetRequiredService<AuthorizationDbContext>()
            .Set<AuthorizeMessage>()
            .Where(x => x.Reference == reference));
    }

    [Fact]
    public async Task PushedAuthorization_DPoPRequestWithoutNonce_ExpectUseDPoPNonce()
    {
        // Arrange
        var identityClient = await AddIdentityProviderClient();

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("web-app")
            .WithRedirectUris(["https://webapp.authserver.dk/callback"])
            .WithGrantTypes([GrantTypeConstants.AuthorizationCode])
            .WithScope([ScopeConstants.UserInfo, ScopeConstants.OpenId])
            .WithRequestUriExpiration(300)
            .Post();

        // Act
        var jwks = ClientJwkBuilder.GetClientJwks();
        var pushedAuthorizationResponse = await PushedAuthorizationEndpointBuilder
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.ClientSecretBasic)
            .WithDPoP(null)
            .WithPrivateJwks(jwks)
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithScope([ScopeConstants.OpenId, ScopeConstants.UserInfo])
            .WithResource([identityClient.ClientUri!])
            .Post();

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, pushedAuthorizationResponse.StatusCode);
        Assert.NotNull(pushedAuthorizationResponse.Error);
        Assert.Equal(ErrorCode.UseDPoPNonce, pushedAuthorizationResponse.Error.Error);
        Assert.Null(pushedAuthorizationResponse.Response);
        Assert.Null(pushedAuthorizationResponse.Location);
        Assert.NotNull(pushedAuthorizationResponse.DPoPNonce);
    }

    [Fact]
    public async Task PushedAuthorization_ValidJwtRequest_ExpectCreated()
    {
        // Arrange
        var identityClient = await AddIdentityProviderClient();

        var jwks = ClientJwkBuilder.GetClientJwks();
        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("web-app")
            .WithRedirectUris(["https://webapp.authserver.dk/callback"])
            .WithGrantTypes([GrantTypeConstants.AuthorizationCode])
            .WithScope([ScopeConstants.UserInfo, ScopeConstants.OpenId])
            .WithRequestUriExpiration(300)
            .WithJwks(jwks.PublicJwks)
            .Post();

        var nonceRepository = ServiceProvider.GetRequiredService<INonceRepository>();
        var nonce = await nonceRepository.CreateDPoPNonce(registerResponse.ClientId, CancellationToken.None);

        // Act
        var pushedAuthorizationResponse = await PushedAuthorizationEndpointBuilder
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.ClientSecretBasic)
            .WithRequest()
            .WithDPoP(nonce)
            .WithDPoPJkt()
            .WithPrivateJwks(jwks)
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithScope([ScopeConstants.OpenId, ScopeConstants.UserInfo])
            .WithResource([identityClient.ClientUri!])
            .Post();

        // Assert
        Assert.Equal(HttpStatusCode.Created, pushedAuthorizationResponse.StatusCode);
        Assert.Null(pushedAuthorizationResponse.Error);
        Assert.NotNull(pushedAuthorizationResponse.Response);
        Assert.NotNull(pushedAuthorizationResponse.Location);
        Assert.Equal(EndpointResolver.AuthorizationEndpoint, pushedAuthorizationResponse.Location.GetLeftPart(UriPartial.Path));
        Assert.Equal(registerResponse.RequestUriExpiration, pushedAuthorizationResponse.Response.ExpiresIn);

        var authorizeRequestQuery = HttpUtility.ParseQueryString(pushedAuthorizationResponse.Location.Query);
        var clientId = authorizeRequestQuery.Get(Parameter.ClientId);
        var requestUri = authorizeRequestQuery.Get(Parameter.RequestUri);
        Assert.Equal(registerResponse.ClientId, clientId);
        Assert.Equal(pushedAuthorizationResponse.Response.RequestUri, requestUri);

        var reference = pushedAuthorizationResponse.Response.RequestUri[RequestUriConstants.RequestUriPrefix.Length..];
        Assert.NotEmpty(reference);

        Assert.Single(ServiceProvider
            .GetRequiredService<AuthorizationDbContext>()
            .Set<AuthorizeMessage>()
            .Where(x => x.Reference == reference));
    }

    [Fact]
    public async Task PushedAuthorization_InvalidRequest_ExpectBadRequest()
    {
        // Arrange
        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("web-app")
            .WithRedirectUris(["https://webapp.authserver.dk/callback"])
            .WithGrantTypes([GrantTypeConstants.AuthorizationCode])
            .WithScope([ScopeConstants.UserInfo, ScopeConstants.OpenId])
            .WithRequestUriExpiration(300)
            .Post();

        // Act
        var pushedAuthorizationResponse = await PushedAuthorizationEndpointBuilder
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.ClientSecretBasic)
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithMaxAge(-1)
            .Post();

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, pushedAuthorizationResponse.StatusCode);
        Assert.NotNull(pushedAuthorizationResponse.Error);
        Assert.Null(pushedAuthorizationResponse.Response);
        Assert.Null(pushedAuthorizationResponse.Location);
    }
}