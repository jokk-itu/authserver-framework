using System.Net;
using System.Text;
using System.Text.Json;
using System.Web;
using AuthServer.Core;
using AuthServer.Endpoints.Abstractions;
using AuthServer.EndSession;
using AuthServer.Options;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Net.Http.Headers;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest.EndpointBuilders;

public class EndSessionEndpointBuilder : EndpointBuilder
{
    private readonly IDataProtectionProvider _dataProtectionProvider;
    private readonly List<KeyValuePair<string, object>> _parameters = [];
    private readonly List<CookieHeaderValue> _cookies = [];

    public EndSessionEndpointBuilder(
        HttpClient httpClient,
        IDataProtectionProvider dataProtectionProvider,
        DiscoveryDocument discoveryDocument,
        JwksDocument jwksDocument,
        IEndpointResolver endpointResolver,
        ITestOutputHelper testOutputHelper)
        : base(httpClient, discoveryDocument, jwksDocument, endpointResolver, testOutputHelper)
    {
        _dataProtectionProvider = dataProtectionProvider;
    }

    public EndSessionEndpointBuilder WithIdTokenHint(string idTokenHint)
    {
        _parameters.Add(new KeyValuePair<string, object>(Parameter.IdTokenHint, idTokenHint));
        return this;
    }

    public EndSessionEndpointBuilder WithClientId(string clientId)
    {
        _parameters.Add(new KeyValuePair<string, object>(Parameter.ClientId, clientId));
        return this;
    }

    public EndSessionEndpointBuilder WithPostLogoutRedirectUri(string postLogoutRedirectUri)
    {
        _parameters.Add(new KeyValuePair<string, object>(Parameter.PostLogoutRedirectUri, postLogoutRedirectUri));
        return this;
    }

    public EndSessionEndpointBuilder WithState(string state)
    {
        _parameters.Add(new KeyValuePair<string, object>(Parameter.State, state));
        return this;
    }

    public EndSessionEndpointBuilder WithEndSessionUser(string subjectIdentifier, bool logoutAtIdentityProvider)
    {
        var dataProtector = _dataProtectionProvider.CreateProtector(EndSessionUserAccessor.DataProtectorName);
        var authorizeUser = new EndSessionUser(subjectIdentifier, logoutAtIdentityProvider);
        var authorizeUserBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(authorizeUser));
        var encryptedAuthorizeUser = dataProtector.Protect(authorizeUserBytes);
        var cookieValue = Convert.ToBase64String(encryptedAuthorizeUser);
        _cookies.Add(new CookieHeaderValue(EndSessionUserAccessor.Cookie, cookieValue));
        return this;
    }

    public async Task<EndSessionResponse> Get() => await Send(fields =>
        new HttpRequestMessage(HttpMethod.Get, $"connect/end-session{new QueryBuilder(fields).ToQueryString()}"));

    public async Task<EndSessionResponse> Post() => await Send(fields =>
        new HttpRequestMessage(HttpMethod.Post, "connect/end-session"){Content = new FormUrlEncodedContent(fields)});

    private async Task<EndSessionResponse> Send(Func<IEnumerable<KeyValuePair<string, string>>, HttpRequestMessage> requestGetter)
    {
        var fields = _parameters.Select(x => new KeyValuePair<string, string>(x.Key, x.Value.ToString()!));
        var requestMessage = requestGetter.Invoke(fields);
        requestMessage.Headers.Add("Cookie", _cookies.Select(x => x.ToString()));
        var response = await HttpClient.SendAsync(requestMessage);
        var content = await response.Content.ReadAsStringAsync();

        TestOutputHelper.WriteLine("Received EndSession response {0}, Location: {1}, Content: {2}",
            response.StatusCode,
            response.Headers.Location,
            content);

        if (response.StatusCode == HttpStatusCode.SeeOther)
        {
            var queryNameValues = HttpUtility.ParseQueryString(response.Headers.Location!.Query);
            return new EndSessionResponse
            {
                StatusCode = response.StatusCode,
                LocationUri = response.Headers.Location!.GetLeftPart(UriPartial.Path),
                State = queryNameValues.Get(Parameter.State)
            };
        }

        return new EndSessionResponse
        {
            StatusCode = response.StatusCode,
            Content = content
        };
    }

    public sealed record EndSessionResponse
    {
        public HttpStatusCode StatusCode { get; init; }
        public string? State { get; init; }
        public string? LocationUri { get; init; }
        public string? Content { get; init; }
    }
}