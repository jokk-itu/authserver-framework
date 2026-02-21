using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Cache.Abstractions;
using AuthServer.Extensions;
using AuthServer.Repositories.Abstractions;
using Microsoft.Extensions.Logging;

namespace AuthServer.Authorization;

internal class ScopeResourceService : IScopeResourceService
{
    private readonly ICachedClientStore _cachedClientStore;
    private readonly IConsentRepository _consentRepository;
    private readonly IClientRepository _clientRepository;
    private readonly ILogger<ScopeResourceService> _logger;

    public ScopeResourceService(
        ICachedClientStore cachedClientStore,
        IConsentRepository consentRepository,
        IClientRepository clientRepository,
        ILogger<ScopeResourceService> logger)
    {
        _cachedClientStore = cachedClientStore;
        _consentRepository = consentRepository;
        _clientRepository = clientRepository;
        _logger = logger;
    }

    /// <inheritdocs/>
    public async Task<ScopeResourceValidationResult> ValidateScopeResourceForGrant(
        IReadOnlyCollection<string> scopes,
        IReadOnlyCollection<string> resources,
        string authorizationGrantId,
        CancellationToken cancellationToken)
    {
        var grantConsentScopes = await _consentRepository.GetGrantConsentedScopes(authorizationGrantId, cancellationToken);
        if (grantConsentScopes.Count == 0)
        {
            return new ScopeResourceValidationResult
            {
                Error = ScopeResourceError.ConsentNotFound
            };
        }

        var requestedScopes = scopes.Count != 0
            ? scopes
            : grantConsentScopes
                .Select(x => x.Name)
                .ToList();

        var requestedResources = resources.Count != 0
            ? resources
            : grantConsentScopes
                .Select(x => x.Resource)
                .Distinct()
                .ToList();

        _logger.LogDebug(
            "Scopes {@Scopes} and Resources {@Resource} deduced for grant {AuthorizationGrantId}",
            requestedScopes,
            requestedResources,
            authorizationGrantId);

        if (requestedScopes.IsNotSubset(grantConsentScopes.Select(x => x.Name)))
        {
            return new ScopeResourceValidationResult
            {
                Error = ScopeResourceError.ScopeExceedsConsent
            };
        }

        if (requestedResources.IsNotSubset(grantConsentScopes.Select(x => x.Resource)))
        {
            return new ScopeResourceValidationResult
            {
                Error = ScopeResourceError.ResourceExceedsConsent
            };
        }

        var areResourcesAuthorizedForScope = await _clientRepository.AreResourcesAuthorizedForScope(
            requestedResources,
            requestedScopes,
            cancellationToken);

        if (!areResourcesAuthorizedForScope)
        {
            return new ScopeResourceValidationResult
            {
                Error = ScopeResourceError.UnauthorizedResourceForScope
            };
        }

        return new ScopeResourceValidationResult
        {
            Scopes = requestedScopes,
            Resources = requestedResources
        };
    }

    /// <inheritdocs/>
    public async Task<ScopeResourceValidationResult> ValidateScopeResourceForClient(
        IReadOnlyCollection<string> scopes,
        IReadOnlyCollection<string> resources,
        string clientId,
        CancellationToken cancellationToken)
    {
        var cachedClient = await _cachedClientStore.Get(clientId, cancellationToken);
        var requestedScopes = scopes.Count == 0 ? cachedClient.Scopes : scopes;
        if (requestedScopes.IsNotSubset(cachedClient.Scopes))
        {
            return new ScopeResourceValidationResult
            {
                Error = ScopeResourceError.UnauthorizedClientForScope
            };
        }

        if (resources.Count == 0)
        {
            throw new ArgumentException("resources must be provided");
        }

        var areResourcesAuthorizedForScope = await _clientRepository.AreResourcesAuthorizedForScope(resources, requestedScopes, cancellationToken);
        if (!areResourcesAuthorizedForScope)
        {
            return new ScopeResourceValidationResult
            {
                Error = ScopeResourceError.UnauthorizedResourceForScope
            };
        }

        return new ScopeResourceValidationResult
        {
            Scopes = requestedScopes,
            Resources = resources
        };
    }
}