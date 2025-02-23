using System.Net.Http.Headers;
using AuthServer.Authorization.Abstractions;
using AuthServer.Cache.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Extensions;
using AuthServer.Repositories.Abstractions;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.Extensions.Logging;

namespace AuthServer.Authorization;

internal class SecureRequestService : ISecureRequestService
{
    private readonly ITokenDecoder<ClientIssuedTokenDecodeArguments> _tokenDecoder;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<SecureRequestService> _logger;
    private readonly IClientRepository _clientRepository;
    private readonly ICachedClientStore _cachedClientStore;

    private AuthorizeRequestDto? _cachedAuthorizeRequestObjectDto;

    public SecureRequestService(
        ITokenDecoder<ClientIssuedTokenDecodeArguments> tokenDecoder,
        IHttpClientFactory httpClientFactory,
        ILogger<SecureRequestService> logger,
        IClientRepository clientRepository,
        ICachedClientStore cachedClientStore)
    {
        _tokenDecoder = tokenDecoder;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _clientRepository = clientRepository;
        _cachedClientStore = cachedClientStore;
    }

    /// <inheritdoc/>
    public AuthorizeRequestDto GetCachedRequest()
    {
        return _cachedAuthorizeRequestObjectDto ??
               throw new InvalidOperationException("authorize request has not been cached");
    }

    /// <inheritdoc/>
    public async Task<AuthorizeRequestDto?> GetRequestByObject(string requestObject, string clientId,
        ClientTokenAudience audience, CancellationToken cancellationToken)
    {
        var client = await _cachedClientStore.Get(clientId, cancellationToken);
        var algorithms = new List<string>();

        if (client.RequestObjectSigningAlg is not null)
        {
            algorithms.Add(client.RequestObjectSigningAlg.GetDescription());
        }

        if (client.RequestObjectEncryptionEnc is not null)
        {
            algorithms.Add(client.RequestObjectEncryptionEnc.GetDescription());
        }

        var jsonWebToken = await _tokenDecoder.Validate(
            requestObject,
            new ClientIssuedTokenDecodeArguments
            {
                ValidateLifetime = true,
                Algorithms = algorithms.AsReadOnly(),
                Audience = audience,
                ClientId = clientId,
                SubjectId = clientId,
                TokenType = TokenTypeHeaderConstants.RequestObjectToken
            },
            cancellationToken);

        if (jsonWebToken is null)
        {
            return null;
        }

        var claims = jsonWebToken.Claims.ToList();
        var clientIdClaim = claims.SingleOrDefault(x => x.Type == Parameter.ClientId);
        var codeChallengeClaim = claims.SingleOrDefault(x => x.Type == Parameter.CodeChallenge);
        var codeChallengeMethodClaim = claims.SingleOrDefault(x => x.Type == Parameter.CodeChallengeMethod);
        var displayClaim = claims.SingleOrDefault(x => x.Type == Parameter.Display);
        var idTokenHintClaim = claims.SingleOrDefault(x => x.Type == Parameter.IdTokenHint);
        var loginHintClaim = claims.SingleOrDefault(x => x.Type == Parameter.LoginHint);
        var maxAgeClaim = claims.SingleOrDefault(x => x.Type == Parameter.MaxAge);
        var nonceClaim = claims.SingleOrDefault(x => x.Type == Parameter.Nonce);
        var redirectUriClaim = claims.SingleOrDefault(x => x.Type == Parameter.RedirectUri);
        var promptClaim = claims.SingleOrDefault(x => x.Type == Parameter.Prompt);
        var responseModeClaim = claims.SingleOrDefault(x => x.Type == Parameter.ResponseMode);
        var responseTypeClaim = claims.SingleOrDefault(x => x.Type == Parameter.ResponseType);
        var stateClaim = claims.SingleOrDefault(x => x.Type == Parameter.State);
        var grantIdClaim = claims.SingleOrDefault(x => x.Type == Parameter.GrantId);
        var grantManagementActionClaim = claims.SingleOrDefault(x => x.Type == Parameter.GrantManagementAction);
        var scopeClaim = claims.SingleOrDefault(x => x.Type == Parameter.Scope);
        var acrValuesClaim = claims.SingleOrDefault(x => x.Type == Parameter.AcrValues);
        var resourceClaims = claims.Where(x => x.Type == Parameter.Resource).ToList();

        _cachedAuthorizeRequestObjectDto = new AuthorizeRequestDto
        {
            ClientId = clientIdClaim?.Value,
            CodeChallenge = codeChallengeClaim?.Value,
            CodeChallengeMethod = codeChallengeMethodClaim?.Value,
            Display = displayClaim?.Value,
            IdTokenHint = idTokenHintClaim?.Value,
            LoginHint = loginHintClaim?.Value,
            MaxAge = maxAgeClaim?.Value,
            Nonce = nonceClaim?.Value,
            RedirectUri = redirectUriClaim?.Value,
            Prompt = promptClaim?.Value,
            ResponseMode = responseModeClaim?.Value,
            ResponseType = responseTypeClaim?.Value,
            State = stateClaim?.Value,
            GrantId = grantIdClaim?.Value,
            GrantManagementAction = grantManagementActionClaim?.Value,
            Scope = scopeClaim?.Value.Split(' ') ?? [],
            AcrValues = acrValuesClaim?.Value.Split(' ') ?? [],
            Resource = resourceClaims.Select(x => x.Value).ToList()
        };

        return _cachedAuthorizeRequestObjectDto;
    }

    /// <inheritdoc/>
    public async Task<AuthorizeRequestDto?> GetRequestByReference(Uri requestUri, string clientId,
        ClientTokenAudience audience, CancellationToken cancellationToken)
    {
        // TODO implement a Timeout to reduce Denial-Of-Service attacks, where a RequestUri recursively calls Authorize
        // TODO implement retry delegate handler (5XX and 429)
        var httpClient = _httpClientFactory.CreateClient(HttpClientNameConstants.Client);
        var request = new HttpRequestMessage(HttpMethod.Get, requestUri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(MimeTypeConstants.OAuthRequestJwt));

        try
        {
            var response = await httpClient.SendAsync(request, cancellationToken);
            response.EnsureSuccessStatusCode();

            var requestObject = await response.Content.ReadAsStringAsync(cancellationToken);
            return await GetRequestByObject(requestObject, clientId, audience, cancellationToken);
        }
        catch (Exception e)
        {
            _logger.LogError(e, "Unexpected error occurred fetching request_object");
            return null;
        }
    }

    /// <inheritdoc/>
    public async Task<AuthorizeRequestDto?> GetRequestByPushedRequest(string requestUri, string clientId,
        CancellationToken cancellationToken)
    {
        var reference = requestUri[RequestUriConstants.RequestUriPrefix.Length..];

        _cachedAuthorizeRequestObjectDto =
            await _clientRepository.GetAuthorizeDto(reference, clientId, cancellationToken);
        return _cachedAuthorizeRequestObjectDto;
    }
}