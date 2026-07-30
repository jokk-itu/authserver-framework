using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Cache.Abstractions;
using AuthServer.Extensions;
using AuthServer.Repositories.Abstractions;
using Microsoft.Extensions.Logging;

namespace AuthServer.Authorization;

internal class TokenAuthorizationValidator : ITokenAuthorizationValidatorService
{
    private readonly ICachedClientStore _cachedClientStore;
    private readonly IConsentRepository _consentRepository;
    private readonly IClientRepository _clientRepository;
    private readonly ILogger<TokenAuthorizationValidator> _logger;

    public TokenAuthorizationValidator(
        ICachedClientStore cachedClientStore,
        IConsentRepository consentRepository,
        IClientRepository clientRepository,
        ILogger<TokenAuthorizationValidator> logger)
    {
        _cachedClientStore = cachedClientStore;
        _consentRepository = consentRepository;
        _clientRepository = clientRepository;
        _logger = logger;
    }

    /// <inheritdocs/>
    public async Task<TokenAuthorizationValidationResult> ValidateTokenAuthorizationGrant(TokenAuthorizationGrantValidationDto validationDto, CancellationToken cancellationToken)
    {
        var grantConsentScopes = await _consentRepository.GetGrantConsentedScopes(validationDto.AuthorizationGrantId, cancellationToken);
        if (grantConsentScopes.Count == 0)
        {
            return new TokenAuthorizationValidationResult
            {
                Error = TokenAuthorizationValidationError.ConsentNotFound
            };
        }

        var requestedScopes = validationDto.Scopes.Count != 0
            ? validationDto.Scopes
            : grantConsentScopes
                .Select(x => x.Name)
                .ToList();

        var requestedResources = validationDto.Resources.Count != 0
            ? validationDto.Resources
            : grantConsentScopes
                .Select(x => x.Resource)
                .Distinct()
                .ToList();

        _logger.LogDebug(
            "Scopes {@Scopes} and Resources {@Resource} deduced for grant {AuthorizationGrantId}",
            requestedScopes,
            requestedResources,
            validationDto.AuthorizationGrantId);

        if (requestedScopes.IsNotSubset(grantConsentScopes.Select(x => x.Name)))
        {
            return new TokenAuthorizationValidationResult
            {
                Error = TokenAuthorizationValidationError.ScopeExceedsConsent
            };
        }

        if (requestedResources.IsNotSubset(grantConsentScopes.Select(x => x.Resource)))
        {
            return new TokenAuthorizationValidationResult
            {
                Error = TokenAuthorizationValidationError.ResourceExceedsConsent
            };
        }

        var areResourcesAuthorizedForScope = await _clientRepository.AreResourcesAuthorizedForScope(
            requestedResources,
            requestedScopes,
            cancellationToken);

        if (!areResourcesAuthorizedForScope)
        {
            return new TokenAuthorizationValidationResult
            {
                Error = TokenAuthorizationValidationError.UnauthorizedResourceForScope
            };
        }

        return new TokenAuthorizationValidationResult
        {
            Scopes = requestedScopes,
            Resources = requestedResources
        };
    }

    /// <inheritdocs/>
    public async Task<TokenAuthorizationValidationResult> ValidateTokenAuthorizationClient(TokenAuthorizationClientValidationDto validationDto, CancellationToken cancellationToken)
    {
        var cachedClient = await _cachedClientStore.Get(validationDto.ClientId, cancellationToken);
        var requestedScopes = validationDto.Scopes.Count == 0 ? cachedClient.Scopes : validationDto.Scopes;
        if (requestedScopes.IsNotSubset(cachedClient.Scopes))
        {
            return new TokenAuthorizationValidationResult
            {
                Error = TokenAuthorizationValidationError.UnauthorizedClientForScope
            };
        }

        if (validationDto.Resources.Count == 0)
        {
            throw new ArgumentException("resources must be provided");
        }

        var areResourcesAuthorizedForScope = await _clientRepository.AreResourcesAuthorizedForScope(validationDto.Resources, requestedScopes, cancellationToken);
        if (!areResourcesAuthorizedForScope)
        {
            return new TokenAuthorizationValidationResult
            {
                Error = TokenAuthorizationValidationError.UnauthorizedResourceForScope
            };
        }

        return new TokenAuthorizationValidationResult
        {
            Scopes = requestedScopes,
            Resources = validationDto.Resources
        };
    }
}