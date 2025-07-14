using AuthServer.Constants;
using AuthServer.Endpoints.Abstractions;
using AuthServer.Endpoints.Responses;
using AuthServer.Enums;
using AuthServer.Helpers;
using AuthServer.Options;
using AuthServer.Tests.Core;
using AuthServer.TokenDecoders;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Web;
using AuthServer.Core;
using AuthServer.DeviceAuthorization;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest.EndpointBuilders;
public class DeviceAuthorizationEndpointBuilder : EndpointBuilder<DeviceAuthorizationEndpointBuilder>
{
    private TokenEndpointAuthMethod _tokenEndpointAuthMethod;
    private bool _isProtectedWithRequestParameter;

    public DeviceAuthorizationEndpointBuilder(
        HttpClient httpClient,
        DiscoveryDocument discoveryDocument,
        JwksDocument jwksDocument,
        IEndpointResolver endpointResolver,
        ITestOutputHelper testOutputHelper)
        : base(httpClient, discoveryDocument, jwksDocument, endpointResolver, testOutputHelper)
    {
    }

    public DeviceAuthorizationEndpointBuilder WithTokenEndpointAuthMethod(
        TokenEndpointAuthMethod tokenEndpointAuthMethod)
    {
        _tokenEndpointAuthMethod = tokenEndpointAuthMethod;
        return this;
    }

    public DeviceAuthorizationEndpointBuilder WithCodeChallenge(string codeChallenge)
    {
        _parameters.Add(new(Parameter.CodeChallenge, codeChallenge));
        return this;
    }

    public DeviceAuthorizationEndpointBuilder WithCodeChallengeMethod(string codeChallengeMethod)
    {
        _parameters.Add(new(Parameter.CodeChallengeMethod, codeChallengeMethod));
        return this;
    }

    public DeviceAuthorizationEndpointBuilder WithClientId(string clientId)
    {
        _parameters.Add(new(Parameter.ClientId, clientId));
        return this;
    }

    public DeviceAuthorizationEndpointBuilder WithClientSecret(string clientSecret)
    {
        _parameters.Add(new(Parameter.ClientSecret, clientSecret));
        return this;
    }

    public DeviceAuthorizationEndpointBuilder WithScope(IReadOnlyCollection<string> scopes)
    {
        _parameters.Add(new(Parameter.Scope, string.Join(' ', scopes)));
        return this;
    }

    public DeviceAuthorizationEndpointBuilder WithResource(IReadOnlyCollection<string> resources)
    {
        resources.ToList().ForEach(x => _parameters.Add(new(Parameter.Resource, x)));
        return this;
    }

    public DeviceAuthorizationEndpointBuilder WithRequest()
    {
        _isProtectedWithRequestParameter = true;
        return this;
    }

    internal async Task<DeviceAuthorizationResponse> Post()
    {
        var httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, "connect/device-authorization");

        SetDefaultValues();
        AddDPoP(httpRequestMessage, "connect/device-authorization");

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
                    ClientTokenAudience.DeviceAuthorizationEndpoint);

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
                ClientTokenAudience.DeviceAuthorizationEndpoint);

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
                ClientTokenAudience.DeviceAuthorizationEndpoint);

            _parameters.Clear();
            _parameters.Add(new(Parameter.Request, requestObject));
            _parameters.Add(new(Parameter.ClientId, clientId));
            _parameters.Add(new(Parameter.ClientAssertion, clientAssertion));
            _parameters.Add(new(Parameter.ClientAssertionType, clientAssertionType));
        }

        httpRequestMessage.Content = new FormUrlEncodedContent(_parameters);
        var httpResponseMessage = await HttpClient.SendAsync(httpRequestMessage);

        TestOutputHelper.WriteLine(
            "Received DeviceAuthorization response {0}, Content: {1}",
            httpResponseMessage.StatusCode,
            await httpResponseMessage.Content.ReadAsStringAsync());

        var content = await httpResponseMessage.Content.ReadAsStringAsync();
        if (httpResponseMessage.StatusCode == HttpStatusCode.OK)
        {
            return new DeviceAuthorizationResponse
            {
                StatusCode = httpResponseMessage.StatusCode,
                Response = JsonSerializer.Deserialize<PostDeviceAuthorizationResponse>(content)
            };
        }

        httpResponseMessage.Headers.TryGetValues(Parameter.DPoPNonce, out var dPoPNonce);
        return new DeviceAuthorizationResponse
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
            _parameters.Add(new(Parameter.CodeChallenge, ProofKeyGenerator.GetProofKeyForCodeExchange().CodeChallenge));
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

    internal class DeviceAuthorizationResponse
    {
        public HttpStatusCode StatusCode { get; set; }
        public OAuthError? Error { get; set; }
        public PostDeviceAuthorizationResponse? Response { get; set; }
        public string? DPoPNonce { get; set; }
    }
}