using System.Net;
using System.Net.Http.Headers;
using AuthServer.Core;
using AuthServer.Entities;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest;
public class DeleteRegisterTest : BaseIntegrationTest
{
    public DeleteRegisterTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
        : base(factory, testOutputHelper)
    {
    }

    [Fact]
    public async Task DeleteRegister_DeleteClient_ExpectDeleted()
    {
        // Arrange
        var client = await RegisterEndpointBuilder
            .WithRedirectUris(["https://webapp.authserver.dk/callback"])
            .WithClientName("webapp")
            .Post();

        var request = new HttpRequestMessage(HttpMethod.Delete, $"connect/register?client_id={client.ClientId}")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", client.RegistrationAccessToken) }
        };
        var httpClient = GetHttpClient();

        // Act
        var response = await httpClient.SendAsync(request);
        response.EnsureSuccessStatusCode();

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        var databaseContext = ServiceProvider.GetRequiredService<AuthorizationDbContext>();
        Assert.Null(await databaseContext.Set<Client>().SingleOrDefaultAsync(c => c.Id == client.ClientId));
    }
}