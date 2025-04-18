using System.Net;
using AuthServer.Authorize;
using AuthServer.Core;
using AuthServer.Options;
using AuthServer.Tests.Core;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using AuthServer.Helpers;
using Microsoft.AspNetCore.Http.Extensions;
using Xunit.Abstractions;
using AuthServer.Constants;
using System.Web;
using System.Text.RegularExpressions;
using AuthServer.Endpoints.Abstractions;
using AuthServer.TokenDecoders;
using ProofKeyForCodeExchangeHelper = AuthServer.Tests.Core.ProofKeyForCodeExchangeHelper;
using AuthServer.Endpoints.Responses;

namespace AuthServer.Tests.IntegrationTest.EndpointBuilders;
public class AuthorizeEndpointBuilder : EndpointBuilder
{
    private readonly IDataProtectionProvider _dataProtectionProvider;

    private bool _isProtectedWithRequestParameter;
    private string? _privateJwks;
    private string _clientId;

    private readonly List<KeyValuePair<string, object>> _parameters = [];
    private readonly List<CookieHeaderValue> _cookies = [];

    public AuthorizeEndpointBuilder(
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

    public AuthorizeEndpointBuilder WithState(string state)
    {
        _parameters.Add(new(Parameter.State, state));
        return this;
    }

    public AuthorizeEndpointBuilder WithResponseMode(string responseMode)
    {
        _parameters.Add(new(Parameter.ResponseMode, responseMode));
        return this;
    }

    public AuthorizeEndpointBuilder WithClientId(string clientId)
    {
        _clientId = clientId;
        _parameters.Add(new(Parameter.ClientId, clientId));
        return this;
    }

    public AuthorizeEndpointBuilder WithPrompt(string prompt)
    {
        _parameters.Add(new(Parameter.Prompt, prompt));
        return this;
    }

    public AuthorizeEndpointBuilder WithScope(IReadOnlyCollection<string> scope)
    {
        _parameters.Add(new(Parameter.Scope, string.Join(' ', scope)));
        return this;
    }

    public AuthorizeEndpointBuilder WithResource(IReadOnlyCollection<string> resources)
    {
        resources.ToList().ForEach(x => _parameters.Add(new(Parameter.Resource, x)));
        return this;
    }

    public AuthorizeEndpointBuilder WithCodeChallenge(string codeChallenge)
    {
        _parameters.Add(new(Parameter.CodeChallenge, codeChallenge));
        return this;
    }

    public AuthorizeEndpointBuilder WithResponseType(string responseType)
    {
        _parameters.Add(new(Parameter.ResponseType, responseType));
        return this;
    }

    public AuthorizeEndpointBuilder WithCodeChallengeMethod(string codeChallengeMethod)
    {
        _parameters.Add(new(Parameter.CodeChallengeMethod, codeChallengeMethod));
        return this;
    }

    public AuthorizeEndpointBuilder WithNonce(string nonce)
    {
        _parameters.Add(new(Parameter.Nonce, nonce));
        return this;
    }

    public AuthorizeEndpointBuilder WithMaxAge(int maxAge)
    {
        _parameters.Add(new(Parameter.MaxAge, maxAge.ToString()));
        return this;
    }

    public AuthorizeEndpointBuilder WithAuthorizeUser(string authorizationGrantId)
    {
        var dataProtector = _dataProtectionProvider.CreateProtector(AuthorizeUserAccessor.DataProtectorName);
        var authorizeUser = new AuthorizeUser(UserConstants.SubjectIdentifier, true, authorizationGrantId);
        var authorizeUserBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(authorizeUser));
        var encryptedAuthorizeUser = dataProtector.Protect(authorizeUserBytes);
        var cookieValue = Convert.ToBase64String(encryptedAuthorizeUser);
        _cookies.Add(new CookieHeaderValue(AuthorizeUserAccessor.Cookie, cookieValue));
        return this;
    }

    public AuthorizeEndpointBuilder WithRequest(string privateJwks)
    {
        _isProtectedWithRequestParameter = true;
        _privateJwks = privateJwks;
        return this;
    }

    public AuthorizeEndpointBuilder WithIdTokenHint(string idToken)
    {
        _parameters.Add(new(Parameter.IdTokenHint, idToken));
        return this;
    }

    public async Task<AuthorizeResponse> Get() => await Send(fields =>
        new HttpRequestMessage(HttpMethod.Get, $"connect/authorize{new QueryBuilder(fields).ToQueryString()}"));

    public async Task<AuthorizeResponse> Post() => await Send(fields =>
        new HttpRequestMessage(HttpMethod.Post, "connect/authorize") { Content = new FormUrlEncodedContent(fields) });

    private async Task<AuthorizeResponse> Send(Func<IEnumerable<KeyValuePair<string, string>>, HttpRequestMessage> requestGetter)
    {
        SetDefaultValues();
        OverwriteForRequestObject();

        var fields = _parameters.Select(x => new KeyValuePair<string, string>(x.Key, x.Value.ToString()!));
        var requestMessage = requestGetter.Invoke(fields);
        requestMessage.Headers.Add("Cookie", _cookies.Select(x => x.ToString()));
        var response = await HttpClient.SendAsync(requestMessage);

        TestOutputHelper.WriteLine("Received Authorize response {0}, Location: {1}, Content: {2}",
            response.StatusCode,
            response.Headers.Location,
            await response.Content.ReadAsStringAsync());


        return await GetAuthorizeResponse(response);
    }

    private static async Task<AuthorizeResponse> GetAuthorizeResponse(HttpResponseMessage response)
    {
        if (response.StatusCode == HttpStatusCode.SeeOther)
        {
            var queryNameValues = HttpUtility.ParseQueryString(
                string.IsNullOrEmpty(response.Headers.Location!.Query)
                    ? response.Headers.Location!.Fragment[1..]
                    : response.Headers.Location!.Query[1..]);

            return new AuthorizeResponse
            {
                StatusCode = HttpStatusCode.SeeOther,
                Code = queryNameValues.Get(Parameter.Code),
                State = queryNameValues.Get(Parameter.State),
                Error = queryNameValues.Get(Parameter.Error),
                ErrorDescription = queryNameValues.Get(Parameter.ErrorDescription),
                ReturnUrl = queryNameValues.Get("returnUrl"),
                LocationUri = response.Headers.Location!.GetLeftPart(UriPartial.Path),
                RequestUri = response.RequestMessage!.RequestUri!.AbsoluteUri!
            };
        }

        if (response.StatusCode == HttpStatusCode.BadRequest)
        {
            var content = await response.Content.ReadAsStringAsync();
            var oAuthError = JsonSerializer.Deserialize<OAuthError>(content)!;
            return new AuthorizeResponse
            {
                StatusCode = HttpStatusCode.BadRequest,
                Error = oAuthError.Error,
                ErrorDescription = oAuthError?.ErrorDescription
            };
        }

        if (response.StatusCode == HttpStatusCode.OK)
        {
            var content = await response.Content.ReadAsStringAsync();
            var action = AuthorizeEndpointRegex.GetFormAction(content);
            var code = AuthorizeEndpointRegex.GetCodeField(content);
            var state = AuthorizeEndpointRegex.GetStateField(content);
            var issuer = AuthorizeEndpointRegex.GetIssuerField(content);
            var error = AuthorizeEndpointRegex.GetErrorField(content);
            var errorDescription = AuthorizeEndpointRegex.GetErrorDescription(content);

            return new AuthorizeResponse
            {
                StatusCode = HttpStatusCode.OK,
                Code = code,
                State = state,
                Issuer = issuer,
                Error = error,
                ErrorDescription = errorDescription,
                LocationUri = action,
                RequestUri = response.RequestMessage!.RequestUri!.AbsoluteUri!
            };
        }

        throw new NotSupportedException();
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

    private void OverwriteForRequestObject()
    {
        if (!_isProtectedWithRequestParameter)
        {
            return;
        }

        var requestObject = JwtBuilder.GetRequestObjectJwt(_parameters.ToDictionary(), _clientId, _privateJwks!, ClientTokenAudience.AuthorizationEndpoint);
        _parameters.Clear();
        _parameters.Add(new(Parameter.Request, requestObject));
        _parameters.Add(new(Parameter.ClientId, _clientId));
    }

    public sealed record AuthorizeResponse
    {
        public HttpStatusCode StatusCode { get; init; }
        public string? Code { get; init; }
        public string? Issuer { get; init; }
        public string? State { get; init; }
        public string? Error { get; init; }
        public string? ErrorDescription { get; init; }

        // Query parameter from local redirects
        public string? ReturnUrl { get; init; }

        // Uri from the Location header
        public string? LocationUri { get; init; }

        public string? RequestUri { get; init; }
    }
}