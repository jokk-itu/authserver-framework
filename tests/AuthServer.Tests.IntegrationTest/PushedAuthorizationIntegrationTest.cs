﻿using System.Net;
using System.Web;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Enums;
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
            .Post();

        // Assert
        Assert.Equal(HttpStatusCode.Created, pushedAuthorizationResponse.StatusCode);
        Assert.Null(pushedAuthorizationResponse.Error);
        Assert.NotNull(pushedAuthorizationResponse.Response);
        Assert.NotNull(pushedAuthorizationResponse.Location);
        Assert.Equal(DiscoveryDocument.AuthorizationEndpoint, pushedAuthorizationResponse.Location.GetLeftPart(UriPartial.Path));
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