using System.Net;
using AuthServer.Constants;
using AuthServer.Options;
using AuthServer.Core;
using AuthServer.Endpoints.Responses;
using AuthServer.Helpers;
using AuthServer.TokenDecoders;
using Xunit.Abstractions;
using AuthServer.Enums;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Web;
using AuthServer.Endpoints.Abstractions;
using ProofKeyForCodeExchangeHelper = AuthServer.Tests.Core.ProofKeyForCodeExchangeHelper;

namespace AuthServer.Tests.IntegrationTest.EndpointBuilders;

public class PushedAuthorizationEndpointBuilder : EndpointBuilder<PushedAuthorizationEndpointBuilder>
{
    private TokenEndpointAuthMethod _tokenEndpointAuthMethod;
    private bool _isProtectedWithRequestParameter;

    public PushedAuthorizationEndpointBuilder(
        HttpClient httpClient,
        DiscoveryDocument discoveryDocument,
        JwksDocument jwksDocument,
        IEndpointResolver endpointResolver,
        ITestOutputHelper testOutputHelper)
        : base(httpClient, discoveryDocument, jwksDocument, endpointResolver, testOutputHelper)
    {
    }

    public PushedAuthorizationEndpointBuilder WithTokenEndpointAuthMethod(
        TokenEndpointAuthMethod tokenEndpointAuthMethod)
    {
        _tokenEndpointAuthMethod = tokenEndpointAuthMethod;
        return this;
    }

    public PushedAuthorizationEndpointBuilder WithClientId(string clientId)
    {
        _parameters.Add(new(Parameter.ClientId, clientId));
        return this;
    }

    public PushedAuthorizationEndpointBuilder WithClientSecret(string clientSecret)
    {
        _parameters.Add(new(Parameter.ClientSecret, clientSecret));
        return this;
    }

    public PushedAuthorizationEndpointBuilder WithScope(IReadOnlyCollection<string> scopes)
    {
        _parameters.Add(new(Parameter.Scope, string.Join(' ', scopes)));
        return this;
    }

    public PushedAuthorizationEndpointBuilder WithResource(IReadOnlyCollection<string> resources)
    {
        resources.ToList().ForEach(x => _parameters.Add(new(Parameter.Resource, x)));
        return this;
    }

    public PushedAuthorizationEndpointBuilder WithMaxAge(int maxAge)
    {
        _parameters.Add(new(Parameter.MaxAge, maxAge.ToString()));
        return this;
    }

    public PushedAuthorizationEndpointBuilder WithRequest()
    {
        _isProtectedWithRequestParameter = true;
        return this;
    }

    internal async Task<PushedAuthorizationResponse> Post()
    {
        var httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, "connect/par");

        SetDefaultValues();
        AddDPoP(httpRequestMessage, "connect/par");

        if (_tokenEndpointAuthMethod == TokenEndpointAuthMethod.ClientSecretBasic)
        {
            var clientId = _parameters.Single(x => x.Key == Parameter.ClientId).Value;
            var clientSecret = _parameters.Single(x => x.Key == Parameter.ClientSecret).Value;
            _parameters.RemoveAll(x => x.Key is Parameter.ClientId or Parameter.ClientSecret);

            if (_isProtectedWithRequestParameter)
            {
                var claims = _parameters
                    .Select(x => new KeyValuePair<string, object>(x.Key, x.Value))
                    .ToDictionary();

                var requestObject = JwtBuilder.GetRequestObjectJwt(
                    claims,
                    clientId,
                    ClientJwks!.PrivateJwks,
                    ClientTokenAudience.PushedAuthorizationEndpoint);

                _parameters.Clear();
                _parameters.Add(new(Parameter.Request, requestObject));
                _parameters.Add(new(Parameter.ClientId, clientId));
            }

            var encodedClientId = HttpUtility.UrlEncode(clientId);
            var encodedClientSecret = HttpUtility.UrlEncode(clientSecret);
            var headerValue = $"{encodedClientId}:{encodedClientSecret}";
            var convertedHeaderValue = Convert.ToBase64String(Encoding.UTF8.GetBytes(headerValue));
            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue("Basic", convertedHeaderValue);
        }
        else if (_tokenEndpointAuthMethod == TokenEndpointAuthMethod.ClientSecretPost && _isProtectedWithRequestParameter)
        {
            var clientId = _parameters.Single(x => x.Key == Parameter.ClientId).Value;
            var clientSecret = _parameters.Single(x => x.Key == Parameter.ClientSecret).Value;
            _parameters.RemoveAll(x => x.Key is Parameter.ClientId or Parameter.ClientSecret);

            var claims = _parameters
                .Select(x => new KeyValuePair<string, object>(x.Key, x.Value))
                .ToDictionary();

            var requestObject = JwtBuilder.GetRequestObjectJwt(
                claims,
                clientId,
                ClientJwks!.PrivateJwks,
                ClientTokenAudience.PushedAuthorizationEndpoint);

            _parameters.Clear();
            _parameters.Add(new(Parameter.Request, requestObject));
            _parameters.Add(new(Parameter.ClientId, clientId));
            _parameters.Add(new(Parameter.ClientSecret, clientSecret));
        }
        else if (_tokenEndpointAuthMethod == TokenEndpointAuthMethod.PrivateKeyJwt && _isProtectedWithRequestParameter)
        {
            var clientId = _parameters.Single(x => x.Key == Parameter.ClientId).Value;
            var clientAssertion = _parameters.Single(x => x.Key == Parameter.ClientAssertion).Value;
            var clientAssertionType = _parameters.Single(x => x.Key == Parameter.ClientAssertionType).Value;
            _parameters.RemoveAll(x => x.Key is Parameter.ClientId or Parameter.ClientAssertion or Parameter.ClientAssertionType);

            var claims = _parameters
                .Select(x => new KeyValuePair<string, object>(x.Key, x.Value))
                .ToDictionary();

            var requestObject = JwtBuilder.GetRequestObjectJwt(
                claims,
                clientId,
                ClientJwks!.PrivateJwks,
                ClientTokenAudience.PushedAuthorizationEndpoint);

            _parameters.Clear();
            _parameters.Add(new(Parameter.Request, requestObject));
            _parameters.Add(new(Parameter.ClientId, clientId));
            _parameters.Add(new(Parameter.ClientAssertion, clientAssertion));
            _parameters.Add(new(Parameter.ClientAssertionType, clientAssertionType));
        }

        httpRequestMessage.Content = new FormUrlEncodedContent(_parameters);
        var httpResponseMessage = await HttpClient.SendAsync(httpRequestMessage);

        TestOutputHelper.WriteLine(
            "Received PushedAuthorization response {0}, Location: {1}, Content: {2}",
            httpResponseMessage.StatusCode,
            httpResponseMessage.Headers.Location,
            await httpResponseMessage.Content.ReadAsStringAsync());
        
        var content = await httpResponseMessage.Content.ReadAsStringAsync();
        if (httpResponseMessage.StatusCode == HttpStatusCode.Created)
        {
            return new PushedAuthorizationResponse
            {
                StatusCode = HttpStatusCode.Created,
                Response = JsonSerializer.Deserialize<PostPushedAuthorizationResponse>(content),
                Location = httpResponseMessage.Headers.Location
            };
        }

        httpResponseMessage.Headers.TryGetValues(Parameter.DPoPNonce, out var dPoPNonce);
        return new PushedAuthorizationResponse
        {
            StatusCode = httpResponseMessage.StatusCode,
            Error = JsonSerializer.Deserialize<OAuthError>(content),
            DPoPNonce = dPoPNonce?.ToString()
        };
    }

    private void SetDefaultValues()
    {
        if (_parameters.All(x => x.Key != Parameter.CodeChallenge))
        {
            _parameters.Add(new(Parameter.CodeChallenge, ProofKeyForCodeExchangeHelper.GetProofKeyForCodeExchange().CodeChallenge));
        }

        if (_parameters.All(x => x.Key != Parameter.CodeChallengeMethod))
        {
            _parameters.Add(new(Parameter.CodeChallengeMethod, CodeChallengeMethodConstants.S256));
        }

        if (_parameters.All(x => x.Key != Parameter.State))
        {
            _parameters.Add(new(Parameter.State, CryptographyHelper.GetRandomString(16)));
        }

        if (_parameters.All(x => x.Key != Parameter.Nonce))
        {
            _parameters.Add(new(Parameter.Nonce, CryptographyHelper.GetRandomString(16)));
        }

        if (_parameters.All(x => x.Key != Parameter.ResponseType))
        {
            _parameters.Add(new(Parameter.ResponseType, ResponseTypeConstants.Code));
        }

        if (_parameters.All(x => x.Key != Parameter.Scope))
        {
            _parameters.Add(new(Parameter.Scope, ScopeConstants.OpenId));
        }
    }

    internal class PushedAuthorizationResponse
    {
        public HttpStatusCode StatusCode { get; set; }
        public OAuthError? Error { get; set; }
        public PostPushedAuthorizationResponse? Response { get; set; }
        public Uri? Location { get; set; }
        public string? DPoPNonce { get; set; }
    }
}