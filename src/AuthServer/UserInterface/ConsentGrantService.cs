using AuthServer.Authentication.Abstractions;
using AuthServer.Cache.Abstractions;
using AuthServer.Entities;
using AuthServer.Repositories.Abstractions;
using AuthServer.UserInterface.Abstractions;
using AuthServer.UserInterface.Models;

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
    public async Task HandleConsent(ConsentDto consentDto, CancellationToken cancellationToken)
    {
        await _consentRepository.CreateOrUpdateClientConsent(new Repositories.Models.ConsentDto
        {
            SubjectIdentifier = consentDto.SubjectIdentifier,
            ClientId = consentDto.ClientId,
            ConsentedScopes = consentDto.ConsentedScopes,
            ConsentedClaims = consentDto.ConsentedClaims,
            ConsentedAuthorizationDetailTypes = consentDto.ConsentedAuthorizationDetailTypes
        }, cancellationToken);
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
            ClientRequiresConsent = cachedClient.RequireConsent,
            Username = username,
            ConsentedScope = consents.OfType<ScopeConsent>().Select(x => x.Scope.Name),
            ConsentedClaims = consents.OfType<ClaimConsent>().Select(x => x.Claim.Name),
            ConsentedAuthorizationDetails = consents.OfType<AuthorizationDetailTypeConsent>().Select(x => x.AuthorizationDetailType.Name)
        };
    }
}