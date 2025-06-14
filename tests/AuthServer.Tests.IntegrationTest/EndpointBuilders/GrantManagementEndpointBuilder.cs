using System.Net;
using System.Net.Http.Headers;
using AuthServer.Endpoints.Abstractions;
using AuthServer.Options;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest.EndpointBuilders;
public class GrantManagementEndpointBuilder : EndpointBuilder<GrantManagementEndpointBuilder>
{
    private string? _token;
    private string? _grantId;

    public GrantManagementEndpointBuilder(
        HttpClient httpClient,
        DiscoveryDocument discoveryDocument,
        JwksDocument jwksDocument,
        IEndpointResolver endpointResolver,
        ITestOutputHelper testOutputHelper)
        : base(httpClient, discoveryDocument, jwksDocument, endpointResolver, testOutputHelper)
    {
    }

    public GrantManagementEndpointBuilder WithToken(string token)
    {
        _token = token;
        return this;
    }

    public GrantManagementEndpointBuilder WithGrantId(string grantId)
    {
        _grantId = grantId;
        return this;
    }

    internal async Task<GrantResponse> Get()
    {
        var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, $"connect/grants/{_grantId}");
        httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        var httpResponseMessage = await HttpClient.SendAsync(httpRequestMessage);
        var content = await httpResponseMessage.Content.ReadAsStringAsync();

        TestOutputHelper.WriteLine(
            "Received GrantQuery response {0}, Content: {1}",
            httpResponseMessage.StatusCode,
            content);

        return new GrantResponse
        {
            StatusCode = httpResponseMessage.StatusCode,
            Content = content,
            WwwAuthenticate = httpResponseMessage.Headers.WwwAuthenticate
        };
    }

    internal async Task<GrantResponse> Delete()
    {
        var httpRequestMessage = new HttpRequestMessage(HttpMethod.Delete, $"connect/grants/{_grantId}");
        httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        var httpResponseMessage = await HttpClient.SendAsync(httpRequestMessage);
        var content = await httpResponseMessage.Content.ReadAsStringAsync();

        TestOutputHelper.WriteLine(
            "Received GrantRevoke response {0}, Content: {1}",
            httpResponseMessage.StatusCode,
            content);

        return new GrantResponse
        {
            StatusCode = httpResponseMessage.StatusCode,
            Content = content,
            WwwAuthenticate = httpResponseMessage.Headers.WwwAuthenticate
        };
    }

    internal class GrantResponse
    {
        public required HttpStatusCode StatusCode { get; init; }
        public string? Content { get; init; }
        public required HttpHeaderValueCollection<AuthenticationHeaderValue> WwwAuthenticate { get; init; }
    }
}
