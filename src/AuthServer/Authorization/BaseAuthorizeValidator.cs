using AuthServer.Cache.Entities;
using AuthServer.Constants;
using AuthServer.Extensions;
using AuthServer.Helpers;
using AuthServer.Options;
using AuthServer.Repositories.Abstractions;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.Extensions.Options;

namespace AuthServer.Authorization;
internal class BaseAuthorizeValidator
{
    private readonly INonceRepository _nonceRepository;
    private readonly IServerTokenDecoder _tokenDecoder;
    private readonly IOptionsSnapshot<DiscoveryDocument> _discoveryDocumentOptions;
    private readonly IAuthorizationGrantRepository _authorizationGrantRepository;
    private readonly IClientRepository _clientRepository;

    public BaseAuthorizeValidator(
        INonceRepository nonceRepository,
        IServerTokenDecoder tokenDecoder,
        IOptionsSnapshot<DiscoveryDocument> discoveryDocumentOptions,
        IAuthorizationGrantRepository authorizationGrantRepository,
        IClientRepository clientRepository)
    {
        _nonceRepository = nonceRepository;
        _tokenDecoder = tokenDecoder;
        _discoveryDocumentOptions = discoveryDocumentOptions;
        _authorizationGrantRepository = authorizationGrantRepository;
        _clientRepository = clientRepository;
    }

    protected static bool HasValidState(string? state) => !string.IsNullOrEmpty(state);

    protected static bool HasValidEmptyRedirectUri(string? redirectUri, CachedClient cachedClient)
        => !string.IsNullOrEmpty(redirectUri) || cachedClient.RedirectUris.Count == 1;

    protected static bool HasValidRedirectUri(string? redirectUri, CachedClient cachedClient)
        => string.IsNullOrEmpty(redirectUri) || cachedClient.RedirectUris.Any(x => x == redirectUri);

    protected static bool HasValidResponseMode(string? responseMode)
        => string.IsNullOrEmpty(responseMode) || ResponseModeConstants.ResponseModes.Contains(responseMode);

    protected static bool HasValidResponseType(string? responseType)
        => !string.IsNullOrEmpty(responseType) && ResponseTypeConstants.ResponseTypes.Contains(responseType);

    protected static bool HasAuthorizedResponseType(string responseType, CachedClient cachedClient)
        => cachedClient.ResponseTypes.Any(x => x == responseType)
        && (responseType != ResponseTypeConstants.Code || cachedClient.GrantTypes.Any(x => x == GrantTypeConstants.AuthorizationCode));

    protected static bool HasDeviceCodeGrantType(CachedClient cachedClient)
        => cachedClient.GrantTypes.Any(x => x == GrantTypeConstants.DeviceCode);

    protected static bool HasValidDisplay(string? display)
        => string.IsNullOrEmpty(display) || DisplayConstants.DisplayValues.Contains(display);

    protected static bool HasValidNonce(string? nonce, string? responseType)
        => responseType == ResponseTypeConstants.None || !string.IsNullOrEmpty(nonce);

    protected static bool HasValidCodeChallengeMethod(string? codeChallengeMethod, string? responseType)
        => responseType == ResponseTypeConstants.None || ProofKeyHelper.IsCodeChallengeMethodValid(codeChallengeMethod);

    protected static bool HasValidCodeChallenge(string? codeChallenge, string? responseType)
        => responseType == ResponseTypeConstants.None || ProofKeyHelper.IsCodeChallengeValid(codeChallenge);

    protected static bool HasValidScope(IReadOnlyCollection<string> scope)
        => scope.Contains(ScopeConstants.OpenId);

    protected static bool HasAuthorizedScope(IReadOnlyCollection<string> scope, CachedClient cachedClient)
        => !scope.IsNotSubset(cachedClient.Scopes);

    protected static bool HasValidMaxAge(string? maxAge)
        => MaxAgeHelper.IsMaxAgeValid(maxAge);

    protected static bool HasValidPrompt(string? prompt)
        => string.IsNullOrEmpty(prompt) || PromptConstants.Prompts.Contains(prompt);

    protected bool HasValidAcrValues(IReadOnlyCollection<string> acrValues)
        => acrValues.Count == 0 || acrValues.IsSubset(_discoveryDocumentOptions.Value.AcrValuesSupported);

    protected async Task<bool> HasUniqueNonce(string? nonce, CancellationToken cancellationToken)
        => string.IsNullOrEmpty(nonce) || !await _nonceRepository.IsNonceReplay(nonce, cancellationToken);

    protected async Task<bool> HasValidResource(IReadOnlyCollection<string> resources, IReadOnlyCollection<string> scopes, CancellationToken cancellationToken)
        => resources.Count != 0 && await _clientRepository.DoesResourcesExist(resources, scopes, cancellationToken);

    protected bool HasValidEmptyRequest(string? requestObject, string? requestUri, bool isRequiredByClient)
        => !string.IsNullOrEmpty(requestObject) || !string.IsNullOrEmpty(requestUri) || (!isRequiredByClient && !_discoveryDocumentOptions.Value.RequireSignedRequestObject);

    protected bool HasValidRequestUriForPushedAuthorization(string? requestUri, bool isRequiredByClient)
        => requestUri?.StartsWith(RequestUriConstants.RequestUriPrefix) == true || (!isRequiredByClient && !_discoveryDocumentOptions.Value.RequirePushedAuthorizationRequests);

    protected static bool HasValidDPoP(string? dPoPJkt, string? dPoP, bool clientRequiresDPoP, string? responseType)
        => responseType == ResponseTypeConstants.None
           || !string.IsNullOrEmpty(dPoPJkt)
           || !string.IsNullOrEmpty(dPoP)
           || !clientRequiresDPoP;

    protected async Task<bool> HasValidIdTokenHint(string? idTokenHint, string clientId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(idTokenHint))
        {
            return true;
        }

        var validatedToken = await _tokenDecoder.Validate(
            idTokenHint,
            new ServerTokenDecodeArguments
            {
                ValidateLifetime = true,
                TokenTypes = [TokenTypeHeaderConstants.IdToken],
                Audiences = [clientId]
            }, cancellationToken);

        return validatedToken is not null;
    }

    protected bool HasValidGrantManagementAction(string? grantId, string? grantManagementAction)
    {
        if (string.IsNullOrEmpty(grantManagementAction)
            && _discoveryDocumentOptions.Value.GrantManagementActionRequired)
        {
            return false;
        }

        var allowedValues = new List<string>
            {
                GrantManagementActionConstants.Create,
                GrantManagementActionConstants.Merge,
                GrantManagementActionConstants.Replace
            }
            .Intersect(GrantManagementActionConstants.GrantManagementActions)
            .ToList();
        
        if (!string.IsNullOrEmpty(grantManagementAction)
            && !allowedValues.Contains(grantManagementAction))
        {
            return false;
        }

        if (string.IsNullOrEmpty(grantManagementAction)
            && !string.IsNullOrEmpty(grantId))
        {
            return false;
        }

        if (grantManagementAction == GrantManagementActionConstants.Create
            && !string.IsNullOrEmpty(grantId))
        {
            return false;
        }

        if (!string.IsNullOrEmpty(grantManagementAction)
            && grantManagementAction != GrantManagementActionConstants.Create
            && string.IsNullOrEmpty(grantId))
        {
            return false;
        }

        return true;
    }

    protected async Task<bool> HasValidGrantId(string? grantId, string clientId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(grantId))
        {
            return true;
        }

        return await _authorizationGrantRepository.IsActiveAuthorizationGrant(grantId, clientId, cancellationToken);
    }
}
