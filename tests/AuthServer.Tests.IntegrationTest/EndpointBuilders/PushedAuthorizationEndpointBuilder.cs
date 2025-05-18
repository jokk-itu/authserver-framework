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
using Microsoft.IdentityModel.Tokens;
using ProofKeyForCodeExchangeHelper = AuthServer.Tests.Core.ProofKeyForCodeExchangeHelper;
using static AuthServer.Tests.Core.ClientJwkBuilder;

namespace AuthServer.Tests.IntegrationTest.EndpointBuilders;

public class PushedAuthorizationEndpointBuilder : EndpointBuilder
{
    private TokenEndpointAuthMethod _tokenEndpointAuthMethod;
    private bool _isProtectedWithRequestParameter;
    private bool _isDPoPProtected;
    private string? _dPoPNonce;
    private bool _isDPoPJktProtected;
    private ClientJwks? _clientJwks;

    private List<KeyValuePair<string, string>> _parameters = [];

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

    public PushedAuthorizationEndpointBuilder WithDPoP(string? nonce)
    {
        _isDPoPProtected = true;
        _dPoPNonce = nonce;
        return this;
    }

    public PushedAuthorizationEndpointBuilder WithDPoPJkt()
    {
        _isDPoPJktProtected = true;
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

    public PushedAuthorizationEndpointBuilder WithPrivateJwks(ClientJwks clientJwks)
    {
        _clientJwks = clientJwks;
        return this;
    }

    internal async Task<PushedAuthorizationResponse> Post()
    {
        var httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, "connect/par");

        SetDefaultValues();

        if (_isDPoPProtected)
        {
            var claims = new Dictionary<string, object>
            {
                { ClaimNameConstants.Htm, HttpMethod.Post.Method },
                { ClaimNameConstants.Htu, $"{HttpClient.BaseAddress}/connect/par" }
            };
            if (_dPoPNonce is not null)
            {
                claims.Add(ClaimNameConstants.Nonce, _dPoPNonce);
            }

            var dPoP = JwtBuilder.GetDPoPToken(
                claims,
                _parameters.Single(x => x.Key == Parameter.ClientId).Value,
                _clientJwks!,
                ClientTokenAudience.PushedAuthorizationEndpoint);

            httpRequestMessage.Headers.Add(Parameter.DPoP, dPoP);

            if (_isDPoPJktProtected)
            {
                var jsonWebKey = new JsonWebKeySet(_clientJwks!.PublicJwks).Keys.Single(x => x.Use == JsonWebKeyUseNames.Sig);
                var dPoPJkt = Base64UrlEncoder.Encode(jsonWebKey.ComputeJwkThumbprint());
                _parameters.Add(new KeyValuePair<string, string>(Parameter.DPoPJkt, dPoPJkt));
            }
        }

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

                var requestObject = JwtBuilder.GetRequestObjectJwt(claims, clientId, _clientJwks!.PrivateJwks, ClientTokenAudience.PushedAuthorizationEndpoint);

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

            var requestObject = JwtBuilder.GetRequestObjectJwt(claims, clientId, _clientJwks!.PrivateJwks, ClientTokenAudience.PushedAuthorizationEndpoint);

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

            var requestObject = JwtBuilder.GetRequestObjectJwt(claims, clientId, _clientJwks!.PrivateJwks, ClientTokenAudience.PushedAuthorizationEndpoint);

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

        return new PushedAuthorizationResponse
        {
            StatusCode = httpResponseMessage.StatusCode,
            Error = JsonSerializer.Deserialize<OAuthError>(content),
            DPoPNonce = httpResponseMessage.Headers.GetValues(Parameter.DPoPNonce).SingleOrDefault()
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