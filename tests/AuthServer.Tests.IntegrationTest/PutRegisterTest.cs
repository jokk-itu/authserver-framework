﻿using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Register;
using AuthServer.TokenBuilders;
using AuthServer.TokenBuilders.Abstractions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest;

public class PutRegisterTest : BaseIntegrationTest
{
    public PutRegisterTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
        : base(factory, testOutputHelper)
    {
    }

    [Fact]
    public async Task PutRegister_DefaultValues_ExpectDefaultValuedClient()
    {
        // Arrange
        var databaseContext = ServiceProvider.GetRequiredService<AuthorizationDbContext>();
        var client = new Client("webapp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        databaseContext.Add(client);
        await databaseContext.SaveChangesAsync();

        var registrationTokenBuilder = ServiceProvider.GetRequiredService<ITokenBuilder<RegistrationTokenArguments>>();
        var registrationToken = await registrationTokenBuilder.BuildToken(new RegistrationTokenArguments
        {
            ClientId = client.Id
        }, CancellationToken.None);
        await databaseContext.SaveChangesAsync();

        var arguments = new Dictionary<string, object>
        {
            { Parameter.ClientName, "webapp" },
            { Parameter.RedirectUris, new[] { "https://webapp.authserver.dk/callback" } }
        };
        var request = new HttpRequestMessage(HttpMethod.Put, $"connect/register?client_id={client.Id}")
        {
            Content = new StringContent(JsonSerializer.Serialize(arguments), Encoding.UTF8, MimeTypeConstants.Json),
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", registrationToken) }
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