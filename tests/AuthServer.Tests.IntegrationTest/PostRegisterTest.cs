﻿using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Register;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest;
public class PostRegisterTest : BaseIntegrationTest
{
    public PostRegisterTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
        : base(factory, testOutputHelper)
    {
    }

    [Fact]
    public async Task PostRegister_AuthorizationCodeAndRefreshToken_ExpectAllValues()
    {
        // Arrange
        var arguments = new Dictionary<string, object>
        {
            { Parameter.ClientName, "webapp" },
            { Parameter.GrantTypes, new[] { GrantTypeConstants.AuthorizationCode, GrantTypeConstants.RefreshToken } },
            { Parameter.RedirectUris, new[] { "https://webapp.authserver.dk/callback" } }
        };
        var request = new HttpRequestMessage(HttpMethod.Post, "connect/register")
        {
            Content = new StringContent(JsonSerializer.Serialize(arguments), Encoding.UTF8, MimeTypeConstants.Json)
        };
        var httpClient = GetHttpClient();

        // Act
        var response = await httpClient.SendAsync(request);
        response.EnsureSuccessStatusCode();
        var registerResponse = await response.Content.ReadFromJsonAsync<GetRegisterResponse>();

        // Assert
        Assert.NotNull(registerResponse);
        Assert.Equal("webapp", registerResponse.ClientName);
        Assert.Collection(
            registerResponse.GrantTypes,
            x => Assert.Equal(GrantTypeConstants.AuthorizationCode, x),
            x => Assert.Equal(GrantTypeConstants.RefreshToken, x));
        Assert.NotNull(registerResponse.RedirectUris);
        Assert.Single(registerResponse.RedirectUris);
        Assert.Single(registerResponse.RedirectUris, x => x == "https://webapp.authserver.dk/callback");
    }

    [Fact]
    public async Task PostRegister_ClientCredentials_ExpectClientCredentialsClient()
    {
        // Arrange
        var arguments = new Dictionary<string, object>
        {
            { Parameter.ClientName, "worker-app" },
            { Parameter.GrantTypes, new[] { GrantTypeConstants.ClientCredentials } }
        };
        var request = new HttpRequestMessage(HttpMethod.Post, "connect/register")
        {
            Content = new StringContent(JsonSerializer.Serialize(arguments), Encoding.UTF8, MimeTypeConstants.Json)
        };
        var httpClient = GetHttpClient();

        // Act
        var response = await httpClient.SendAsync(request);
        response.EnsureSuccessStatusCode();
        var registerResponse = await response.Content.ReadFromJsonAsync<GetRegisterResponse>();

        // Assert
        Assert.NotNull(registerResponse);
        Assert.Equal("worker-app", registerResponse.ClientName);
        Assert.Single(registerResponse.GrantTypes);
        Assert.Single(registerResponse.GrantTypes, x => x == GrantTypeConstants.ClientCredentials);
    }

    [Fact]
    public async Task PostRegister_DefaultValues_ExpectDefaultValuedClient()
    {
        // Arrange
        var arguments = new Dictionary<string, object>
        {
            { Parameter.ClientName, "webapp" },
            { Parameter.RedirectUris, new[] { "https://webapp.authserver.dk/callback" } }
        };
        var request = new HttpRequestMessage(HttpMethod.Post, "connect/register")
        {
            Content = new StringContent(JsonSerializer.Serialize(arguments), Encoding.UTF8, MimeTypeConstants.Json)
        };
        var httpClient = GetHttpClient();

        // Act
        var response = await httpClient.SendAsync(request);
        response.EnsureSuccessStatusCode();
        var registerResponse = await response.Content.ReadFromJsonAsync<GetRegisterResponse>();

        // Assert
        Assert.NotNull(registerResponse);
        Assert.Equal("webapp", registerResponse.ClientName);

        Assert.NotNull(registerResponse.RedirectUris);
        Assert.Single(registerResponse.RedirectUris);
        Assert.Single(registerResponse.RedirectUris, x => x == "https://webapp.authserver.dk/callback");

        Assert.Single(registerResponse.GrantTypes);
        Assert.Single(registerResponse.GrantTypes, x => x == GrantTypeConstants.AuthorizationCode);

        Assert.Equal(ApplicationTypeConstants.Web, registerResponse.ApplicationType);
        Assert.Equal(TokenEndpointAuthMethodConstants.ClientSecretBasic, registerResponse.TokenEndpointAuthMethod);
        Assert.Equal(SubjectTypeConstants.Public, registerResponse.SubjectType);
        Assert.Equal(JwsAlgConstants.RsaSha256, registerResponse.IdTokenSignedResponseAlg);
    }
}