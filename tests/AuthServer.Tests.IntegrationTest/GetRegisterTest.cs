using System.Net.Http.Headers;
using System.Net.Http.Json;
using AuthServer.Constants;
using AuthServer.Register;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest;
public class GetRegisterTest : BaseIntegrationTest
{
    public GetRegisterTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
        : base(factory, testOutputHelper)
    {
    }

    [Fact]
    public async Task GetRegister_DefaultValues_ExpectDefaultValuedClient()
    {
        // Arrange
        var client = await RegisterEndpointBuilder
            .WithRedirectUris(["https://webapp.authserver.dk/callback"])
            .WithClientName("webapp")
            .Post();

        var request = new HttpRequestMessage(HttpMethod.Get, $"connect/register?client_id={client.ClientId}")
        {
            Headers = { Authorization = new AuthenticationHeaderValue("Bearer", client.RegistrationAccessToken) }
        };
        var httpClient = GetHttpClient();

        // Act
        var response = await httpClient.SendAsync(request);
        response.EnsureSuccessStatusCode();
        var registerResponse = await response.Content.ReadFromJsonAsync<GetRegisterResponse>();

        // Assert
        Assert.NotNull(registerResponse);
        Assert.Equal("webapp", registerResponse.ClientName);
        Assert.Equal(ApplicationTypeConstants.Web, registerResponse.ApplicationType);
        Assert.Equal(TokenEndpointAuthMethodConstants.ClientSecretBasic, registerResponse.TokenEndpointAuthMethod);
    }
}
