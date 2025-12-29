using System.Net;
using System.Net.Http.Headers;
using AuthServer.Endpoints.Abstractions;
using AuthServer.Options;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest.EndpointBuilders;

public class UserinfoEndpointBuilder : EndpointBuilder<UserinfoEndpointBuilder>
{
    private string? _token;

    public UserinfoEndpointBuilder(
        HttpClient httpClient,
        DiscoveryDocument discoveryDocument,
        JwksDocument jwksDocument,
        IEndpointResolver endpointResolver,
        ITestOutputHelper testOutputHelper)
        : base(httpClient, discoveryDocument, jwksDocument, endpointResolver, testOutputHelper)
    {
    }

    public UserinfoEndpointBuilder WithAccessToken(string token)
    {
        _token = token;
        return this;
    }

    internal async Task<UserinfoResponse> Get()
    {
        var httpRequestMessage = new HttpRequestMessage(HttpMethod.Get, "connect/userinfo");
        httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        var httpResponseMessage = await HttpClient.SendAsync(httpRequestMessage);
        var content = await httpResponseMessage.Content.ReadAsStringAsync();

        TestOutputHelper.WriteLine(
            "Received Userinfo response {0}, Content: {1}",
            httpResponseMessage.StatusCode,
            content);

        return new UserinfoResponse
        {
            StatusCode = httpResponseMessage.StatusCode,
            Content = content,
            ContentType = httpResponseMessage.Content.Headers.ContentType,
            WwwAuthenticate = httpResponseMessage.Headers.WwwAuthenticate
        };
    }

    internal async Task<UserinfoResponse> Post()
    {
        var httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, "connect/userinfo");
        httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        var httpResponseMessage = await HttpClient.SendAsync(httpRequestMessage);
        var content = await httpResponseMessage.Content.ReadAsStringAsync();

        TestOutputHelper.WriteLine(
            "Received Userinfo response {0}, Content: {1}",
            httpResponseMessage.StatusCode,
            content);

        return new UserinfoResponse
        {
            StatusCode = httpResponseMessage.StatusCode,
            Content = content,
            ContentType = httpResponseMessage.Content.Headers.ContentType,
            WwwAuthenticate = httpResponseMessage.Headers.WwwAuthenticate
        };
    }
    
    internal class UserinfoResponse
    {
        public required HttpStatusCode StatusCode { get; init; }
        public string? Content { get; init; }
        public MediaTypeHeaderValue? ContentType { get; init; }
        public required HttpHeaderValueCollection<AuthenticationHeaderValue> WwwAuthenticate { get; init; }
    }
}