using System.Net;
using AuthServer.Enums;
using AuthServer.Options;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Web;
using AuthServer.Core;
using AuthServer.Endpoints.Abstractions;
using AuthServer.Endpoints.Responses;
using AuthServer.Introspection;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest.EndpointBuilders;

public class IntrospectionEndpointBuilder : EndpointBuilder<IntrospectionEndpointBuilder>
{
    private TokenEndpointAuthMethod _tokenEndpointAuthMethod;

    public IntrospectionEndpointBuilder(
        HttpClient httpClient,
        DiscoveryDocument discoveryDocument,
        JwksDocument jwksDocument,
        IEndpointResolver endpointResolver,
        ITestOutputHelper testOutputHelper)
        : base(httpClient, discoveryDocument, jwksDocument, endpointResolver, testOutputHelper)
    {
    }

    public IntrospectionEndpointBuilder WithTokenTypeHint(string tokenTypeHint)
    {
        _parameters.Add(new(Parameter.TokenTypeHint, tokenTypeHint));
        return this;
    }

    public IntrospectionEndpointBuilder WithToken(string token)
    {
        _parameters.Add(new(Parameter.Token, token));
        return this;
    }

    public IntrospectionEndpointBuilder WithClientId(string clientId)
    {
        _parameters.Add(new(Parameter.ClientId, clientId));
        return this;
    }

    public IntrospectionEndpointBuilder WithClientSecret(string clientSecret)
    {
        _parameters.Add(new(Parameter.ClientSecret, clientSecret));
        return this;
    }

    public IntrospectionEndpointBuilder WithTokenEndpointAuthMethod(TokenEndpointAuthMethod tokenEndpointAuthMethod)
    {
        _tokenEndpointAuthMethod = tokenEndpointAuthMethod;
        return this;
    }

    internal async Task<IntrospectionResponse> Post()
    {
        var httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, "connect/introspection");

        if (_tokenEndpointAuthMethod == TokenEndpointAuthMethod.ClientSecretBasic)
        {
            var clientId = _parameters.Single(x => x.Key == Parameter.ClientId).Value;
            var clientSecret = _parameters.Single(x => x.Key == Parameter.ClientSecret).Value;
            
            _parameters.RemoveAll(x => x.Key is Parameter.ClientId or Parameter.ClientSecret);

            var encodedClientId = HttpUtility.UrlEncode(clientId);
            var encodedClientSecret = HttpUtility.UrlEncode(clientSecret);
            var headerValue = $"{encodedClientId}:{encodedClientSecret}";
            var convertedHeaderValue = Convert.ToBase64String(Encoding.UTF8.GetBytes(headerValue));
            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue("Basic", convertedHeaderValue);
        }

        httpRequestMessage.Content = new FormUrlEncodedContent(_parameters);
        var httpResponseMessage = await HttpClient.SendAsync(httpRequestMessage);

        TestOutputHelper.WriteLine(
            "Received Introspection response {0}, Content: {1}",
            httpResponseMessage.StatusCode,
            await httpResponseMessage.Content.ReadAsStringAsync());

        if (httpResponseMessage.StatusCode == HttpStatusCode.OK)
        {
            var response = await httpResponseMessage.Content.ReadFromJsonAsync<PostIntrospectionResponse>()!;
            return new IntrospectionResponse
            {
                StatusCode = httpResponseMessage.StatusCode,
                Response = response
            };
        }

        var error = await httpResponseMessage.Content.ReadFromJsonAsync<OAuthError>()!;
        return new IntrospectionResponse
        {
            StatusCode = httpResponseMessage.StatusCode,
            Error = error
        };
    }

    internal class IntrospectionResponse
    {
        public HttpStatusCode StatusCode { get; set; }
        public OAuthError? Error { get; set; }
        public PostIntrospectionResponse? Response { get; set; }
    }
}