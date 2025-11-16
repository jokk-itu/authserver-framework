using AuthServer.Authentication.Abstractions;
using AuthServer.Authentication.Models;
using AuthServer.Authorization.Abstractions;
using AuthServer.Cache.Entities;
using AuthServer.Core.Request;
using AuthServer.Extensions;
using AuthServer.Repositories.Abstractions;
using AuthServer.Repositories.Models;

namespace AuthServer.TokenByGrant;
internal abstract class BaseTokenValidator
{
    private readonly IDPoPService _dPoPService;
    private readonly IClientAuthenticationService _clientAuthenticationService;
    private readonly IConsentRepository _consentRepository;
    private readonly IClientRepository _clientRepository;

    protected BaseTokenValidator(
        IDPoPService dPoPService,
        IClientAuthenticationService clientAuthenticationService,
        IConsentRepository consentRepository,
        IClientRepository clientRepository)
    {
        _dPoPService = dPoPService;
        _clientAuthenticationService = clientAuthenticationService;
        _consentRepository = consentRepository;
        _clientRepository = clientRepository;
    }

    protected async Task<ProcessResult<string, ProcessError>> AuthenticateClient(IReadOnlyCollection<ClientAuthentication> clientAuthentications, CancellationToken cancellationToken)
    {
        if (clientAuthentications.Count != 1)
        {
            return TokenError.MultipleOrNoneClientMethod;
        }

        var clientAuthentication = clientAuthentications.Single();
        var clientAuthenticationResult = await _clientAuthenticationService.AuthenticateClient(clientAuthentication, cancellationToken);
        if (!clientAuthenticationResult.IsAuthenticated || string.IsNullOrWhiteSpace(clientAuthenticationResult.ClientId))
        {
            return TokenError.InvalidClient;
        }

        return clientAuthenticationResult.ClientId;
    }

    protected async Task<ProcessResult<IReadOnlyCollection<string>, ProcessError>> ValidateScope(IReadOnlyCollection<string> scope, IReadOnlyCollection<string> resource, string? authorizationGrantId, CachedClient cachedClient, CancellationToken cancellationToken)
    {
        IReadOnlyCollection<string> requestedScopes;
        var isScopeRequested = scope.Count != 0;
        if (cachedClient.RequireConsent && authorizationGrantId is not null)
        {
            var grantConsentScopes = await _consentRepository.GetGrantConsentedScopes(authorizationGrantId, cancellationToken);
            if (grantConsentScopes.Count == 0)
            {
                return TokenError.ConsentRequired;
            }

            requestedScopes = isScopeRequested ? scope : grantConsentScopes.Select(x => x.Name).ToList();
            if (requestedScopes.SelectMany(_ => resource, (x, y) => new ScopeDto(x, y)).IsNotSubset(grantConsentScopes))
            {
                return TokenError.ScopeExceedsConsentedScope;
            }
        }
        else
        {
            requestedScopes = isScopeRequested ? scope : cachedClient.Scopes;
        }

        if (requestedScopes.IsNotSubset(cachedClient.Scopes))
        {
            return TokenError.UnauthorizedForScope;
        }

        var doesResourceExist = await _clientRepository.DoesResourcesExist(resource, requestedScopes, cancellationToken);
        if (!doesResourceExist)
        {
            return TokenError.InvalidResource;
        }

        return new ProcessResult<IReadOnlyCollection<string>, ProcessError>(requestedScopes);
    }

    protected async Task<DPoPResult?> ValidateDPoP(string? dPoP, CachedClient cachedClient, string? jkt, CancellationToken cancellationToken)
    {
        var isDPoPRequired = cachedClient.RequireDPoPBoundAccessTokens || jkt is not null;
        if (isDPoPRequired && string.IsNullOrEmpty(dPoP))
        {
            return new DPoPResult
            {
                Error = TokenError.DPoPRequired
            };
        }

        if (string.IsNullOrEmpty(dPoP))
        {
            return null;
        }

        var dPoPValidationResult = await _dPoPService.ValidateDPoP(dPoP, cachedClient.Id, cancellationToken);
        if (dPoPValidationResult is { IsValid: false, RenewDPoPNonce: false })
        {
            return new DPoPResult
            {
                Error = TokenError.InvalidDPoP
            };
        }

        if (dPoPValidationResult is { IsValid: false, RenewDPoPNonce: true })
        {
            return new DPoPResult
            {
                Error = TokenError.RenewDPoPNonce(cachedClient.Id)
            };
        }

        if (jkt is not null && dPoPValidationResult.DPoPJkt != jkt)
        {
            return new DPoPResult
            {
                Error = TokenError.InvalidDPoPJktMatch
            };
        }

        return new DPoPResult
        {
            DPoPJkt = dPoPValidationResult.DPoPJkt
        };
    }

    protected class DPoPResult
    {
        public string? DPoPJkt { get; init; }
        public ProcessError? Error { get; init; }
    }
}