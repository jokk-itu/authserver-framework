using AuthServer.Authentication.Abstractions;
using AuthServer.Cache.Abstractions;
using AuthServer.Entities;
using AuthServer.Repositories.Abstractions;
using AuthServer.UserInterface.Abstractions;

namespace AuthServer.UserInterface;

internal class ConsentGrantService : IConsentGrantService
{
    private readonly IConsentRepository _consentRepository;
    private readonly ICachedClientStore _cachedClientStore;
    private readonly IUserClaimService _userClaimService;

    public ConsentGrantService(
        IConsentRepository consentRepository,
        ICachedClientStore cachedClientStore,
        IUserClaimService userClaimService)
    {
        _consentRepository = consentRepository;
        _cachedClientStore = cachedClientStore;
        _userClaimService = userClaimService;
    }

    /// <inheritdoc/>
    public async Task HandleConsent(string subjectIdentifier, string clientId, IReadOnlyCollection<string> consentedScopes, IReadOnlyCollection<string> consentedClaims, CancellationToken cancellationToken)
    {
        await _consentRepository.CreateOrUpdateClientConsent(subjectIdentifier, clientId, consentedScopes, consentedClaims, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<ConsentGrantDto> GetConsentGrantDto(string subjectIdentifier, string clientId, CancellationToken cancellationToken)
    {
        var consents = await _consentRepository.GetClientConsents(subjectIdentifier, clientId, cancellationToken);
        var cachedClient = await _cachedClientStore.Get(clientId, cancellationToken);
        var username = await _userClaimService.GetUsername(subjectIdentifier, cancellationToken);

        return new ConsentGrantDto
        {
            ClientName = cachedClient.Name,
            ClientLogoUri = cachedClient.LogoUri,
            ClientUri = cachedClient.ClientUri,
            Username = username,
            ConsentedScope = consents.OfType<ScopeConsent>().Select(x => x.Scope.Name),
            ConsentedClaims = consents.OfType<ClaimConsent>().Select(x => x.Claim.Name)
        };
    }
}