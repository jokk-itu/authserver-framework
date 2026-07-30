using System.Text.Json;
using AuthServer.Authorization.Models;
using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Helpers;
using AuthServer.Repositories.Abstractions;
using AuthServer.Repositories.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.Repositories;
internal class ConsentRepository : IConsentRepository
{
    private readonly AuthorizationDbContext _identityContext;

    public ConsentRepository(AuthorizationDbContext identityContext)
    {
        _identityContext = identityContext;
    }

    /// <inheritdoc/>
    public async Task CreateGrantConsent(AuthorizationGrantConsentDto grantConsentDto, CancellationToken cancellationToken)
    {
        var authorizationGrant = await GetAuthorizationGrant(grantConsentDto.AuthorizationGrantId, cancellationToken);
        await UpdateGrantConsent(authorizationGrant, grantConsentDto, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task MergeGrantConsent(AuthorizationGrantConsentDto grantConsentDto, CancellationToken cancellationToken)
    {
        var authorizationGrant = await GetAuthorizationGrant(grantConsentDto.AuthorizationGrantId, cancellationToken);
        await UpdateGrantConsent(authorizationGrant, grantConsentDto, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task ReplaceGrantConsent(AuthorizationGrantConsentDto grantConsentDto, CancellationToken cancellationToken)
    {
        var authorizationGrant = await GetAuthorizationGrant(grantConsentDto.AuthorizationGrantId, cancellationToken);

        authorizationGrant.AuthorizationGrantConsents.Clear();
        await _identityContext.SaveChangesAsync(cancellationToken);

        await UpdateGrantConsent(authorizationGrant, grantConsentDto, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<IReadOnlyCollection<AuthorizationGrantConsent>> GetGrantConsents(string authorizationGrantId, CancellationToken cancellationToken)
    {
        return await _identityContext
            .Set<AuthorizationGrantConsent>()
            .Where(x => x.AuthorizationGrant.Id == authorizationGrantId)
            .Include(x => x.Consent)
            .ThenInclude(x => ((ScopeConsent)x).Scope)
            .Include(x => x.Consent)
            .ThenInclude(x => ((ClaimConsent)x).Claim)
            .Include(x => x.Consent)
            .ThenInclude(x => ((AuthorizationDetailTypeConsent)x).AuthorizationDetailType)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<IReadOnlyCollection<ScopeDto>> GetGrantConsentedScopes(string authorizationGrantId, CancellationToken cancellationToken)
    {
        return await _identityContext
            .Set<AuthorizationGrantScopeConsent>()
            .Where(x => x.AuthorizationGrant.Id == authorizationGrantId)
            .Select(x => new ScopeDto(((ScopeConsent)x.Consent).Scope.Name, x.Resource))
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<IReadOnlyCollection<string>> GetGrantConsentedClaims(string authorizationGrantId, CancellationToken cancellationToken)
    {
        return await _identityContext
            .Set<AuthorizationGrantClaimConsent>()
            .Where(x => x.AuthorizationGrant.Id == authorizationGrantId)
            .Select(x => ((ClaimConsent)x.Consent).Claim.Name)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<IReadOnlyCollection<string>> GetGrantConsentedAuthorizationDetails(string authorizationGrantId, CancellationToken cancellationToken)
    {
        return await _identityContext
            .Set<AuthorizationGrantAuthorizationDetailTypeConsent>()
            .Where(x => x.AuthorizationGrant.Id == authorizationGrantId)
            .Select(x => x.RawValue)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<IReadOnlyCollection<Consent>> GetClientConsents(string subjectIdentifier, string clientId, CancellationToken cancellationToken)
    {
        return await _identityContext
            .Set<Consent>()
            .Where(x => x.Client.Id == clientId)
            .Where(x => x.SubjectIdentifier.Id == subjectIdentifier)
            .Include(x => ((ScopeConsent)x).Scope)
            .Include(x => ((ClaimConsent)x).Claim)
            .Include(x => ((AuthorizationDetailTypeConsent)x).AuthorizationDetailType)
            .ToListAsync(cancellationToken);
    }
    
    /// <inheritdoc/>
    public async Task<IReadOnlyCollection<string>> GetClientConsentedScopes(string subjectIdentifier, string clientId, CancellationToken cancellationToken)
    {
        return await _identityContext
            .Set<ScopeConsent>()
            .Where(x => x.SubjectIdentifier.Id == subjectIdentifier)
            .Where(x => x.Client.Id == clientId)
            .Select(x => x.Scope.Name)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<IReadOnlyCollection<string>> GetClientConsentedClaims(string subjectIdentifier, string clientId, CancellationToken cancellationToken)
    {
        return await _identityContext
            .Set<ClaimConsent>()
            .Where(x => x.SubjectIdentifier.Id == subjectIdentifier)
            .Where(x => x.Client.Id == clientId)
            .Select(x => x.Claim.Name)
            .ToListAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task CreateOrUpdateClientConsent(ConsentDto consentDto, CancellationToken cancellationToken)
    {
        var clientConsents = await GetClientConsents(consentDto.SubjectIdentifier, consentDto.ClientId, cancellationToken);
        await UpdateScopeConsents(consentDto, clientConsents, cancellationToken);
        await UpdateClaimConsents(consentDto, clientConsents, cancellationToken);
        await UpdateAuthorizationDetailTypeConsents(consentDto, clientConsents, cancellationToken);
        await _identityContext.SaveChangesAsync(cancellationToken);
    }

    private async Task UpdateScopeConsents(ConsentDto consentDto, IReadOnlyCollection<Consent> clientConsents, CancellationToken cancellationToken)
    {
        var subject = (await _identityContext.FindAsync<SubjectIdentifier>([consentDto.SubjectIdentifier], cancellationToken))!;
        var client = (await _identityContext.FindAsync<Client>([consentDto.ClientId], cancellationToken))!;

        var scopeToAdd = consentDto.ConsentedScopes
            .Where(x => clientConsents.OfType<ScopeConsent>().All(y => y.Scope.Name != x))
            .ToList();

        var scopeEntities = await _identityContext
            .Set<Scope>()
            .Where(x => scopeToAdd.Contains(x.Name))
            .ToListAsync(cancellationToken);

        foreach (var scope in scopeToAdd)
        {
            var scopeConsent = new ScopeConsent(subject, client, scopeEntities.Single(x => x.Name == scope));
            await _identityContext.AddAsync(scopeConsent, cancellationToken);
        }
    }

    private async Task UpdateClaimConsents(ConsentDto consentDto, IReadOnlyCollection<Consent> clientConsents, CancellationToken cancellationToken)
    {
        var subject = (await _identityContext.FindAsync<SubjectIdentifier>([consentDto.SubjectIdentifier], cancellationToken))!;
        var client = (await _identityContext.FindAsync<Client>([consentDto.ClientId], cancellationToken))!;

        var claims = consentDto.ConsentedClaims;
        var claimsToAdd = claims
            .Where(x => clientConsents.OfType<ClaimConsent>().All(y => y.Claim.Name != x))
            .ToList();

        var claimEntities = await _identityContext
            .Set<Claim>()
            .Where(x => claimsToAdd.Contains(x.Name))
            .ToListAsync(cancellationToken);

        foreach (var claim in claimsToAdd)
        {
            var claimConsent = new ClaimConsent(subject, client, claimEntities.Single(x => x.Name == claim));
            await _identityContext.AddAsync(claimConsent, cancellationToken);
        }

        var claimsToRemove = clientConsents
            .OfType<ClaimConsent>()
            .Where(x => !claims.Contains(x.Claim.Name))
            .ToList();

        _identityContext.RemoveRange(claimsToRemove);
    }

    private async Task UpdateAuthorizationDetailTypeConsents(ConsentDto consentDto, IReadOnlyCollection<Consent> clientConsents, CancellationToken cancellationToken)
    {
        var subject = (await _identityContext.FindAsync<SubjectIdentifier>([consentDto.SubjectIdentifier], cancellationToken))!;
        var client = (await _identityContext.FindAsync<Client>([consentDto.ClientId], cancellationToken))!;

        var authorizationDetailTypes = consentDto.ConsentedAuthorizationDetailTypes;
        var authorizationDetailTypesToAdd = authorizationDetailTypes
            .Where(x => clientConsents.OfType<AuthorizationDetailTypeConsent>().All(y => y.AuthorizationDetailType.Name != x))
            .ToList();

        var authorizationDetailTypeEntities = await _identityContext
            .Set<AuthorizationDetailType>()
            .Where(x => authorizationDetailTypesToAdd.Contains(x.Name))
            .ToListAsync(cancellationToken);

        foreach (var authorizationDetailType in authorizationDetailTypesToAdd)
        {
            var authorizationDetailTypeConsent = new AuthorizationDetailTypeConsent(subject, client, authorizationDetailTypeEntities.Single(x => x.Name == authorizationDetailType));
            await _identityContext.AddAsync(authorizationDetailTypeConsent, cancellationToken);
        }
    }

    private async Task UpdateGrantConsent(AuthorizationGrant authorizationGrant, AuthorizationGrantConsentDto grantConsentDto, CancellationToken cancellationToken)
    {
        var clientConsents = await GetClientConsents(authorizationGrant.Session.SubjectIdentifier.Id, authorizationGrant.Client.Id, cancellationToken);
        AddGrantScopeConsent(authorizationGrant, clientConsents, grantConsentDto.Scope, grantConsentDto.Resource);
        AddGrantClaimConsent(authorizationGrant, clientConsents);
        AddGrantAuthorizationDetailTypeConsent(authorizationGrant, clientConsents, grantConsentDto.AuthorizationDetails);
    }

    private static void AddGrantScopeConsent(AuthorizationGrant authorizationGrant, IReadOnlyCollection<Consent> clientConsents, IReadOnlyCollection<string> scopes, IReadOnlyCollection<string> resources)
    {
        foreach (var scope in scopes)
        {
            var scopeConsent = clientConsents
                .OfType<ScopeConsent>()
                .Single(x => x.Scope.Name == scope);

            foreach (var resource in resources)
            {
                var authorizationGrantScopeConsent = authorizationGrant.AuthorizationGrantConsents
                    .OfType<AuthorizationGrantScopeConsent>()
                    .Where(x => x.Resource == resource)
                    .SingleOrDefault(x => (x.Consent as ScopeConsent)!.Scope.Name == scope);

                if (authorizationGrantScopeConsent is null)
                {
                    authorizationGrantScopeConsent = new AuthorizationGrantScopeConsent(scopeConsent, authorizationGrant, resource);
                    authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantScopeConsent);
                }
            }
        }
    }

    private static void AddGrantClaimConsent(AuthorizationGrant authorizationGrant, IReadOnlyCollection<Consent> clientConsents)
    {
        var fullConsentedScopes = authorizationGrant.AuthorizationGrantConsents
            .OfType<AuthorizationGrantScopeConsent>()
            .Select(x => x.Consent)
            .OfType<ScopeConsent>()
            .Select(x => x.Scope.Name)
            .ToList();

        var fullRequestedClaims = ClaimsHelper.MapToClaims(fullConsentedScopes);
        var fullConsentedClaims = clientConsents
            .OfType<ClaimConsent>()
            .Select(x => x.Claim.Name)
            .Where(x => fullRequestedClaims.Contains(x))
            .ToList();

        foreach (var claim in fullConsentedClaims)
        {
            var claimConsent = clientConsents
                .OfType<ClaimConsent>()
                .Single(x => x.Claim.Name == claim);

            var authorizationGrantClaimConsent = authorizationGrant.AuthorizationGrantConsents
                .OfType<AuthorizationGrantClaimConsent>()
                .SingleOrDefault(x => (x.Consent as ClaimConsent)!.Claim.Name == claim);

            if (authorizationGrantClaimConsent is null)
            {
                authorizationGrantClaimConsent = new AuthorizationGrantClaimConsent(claimConsent, authorizationGrant);
                authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantClaimConsent);
            }
        }
    }

    private static void AddGrantAuthorizationDetailTypeConsent(AuthorizationGrant authorizationGrant, IReadOnlyCollection<Consent> clientConsents, IReadOnlyCollection<AuthorizationDetailDto> authorizationDetails)
    {
        foreach (var authorizationDetail in authorizationDetails)
        {
            var authorizationDetailTypeConsent = clientConsents
                .OfType<AuthorizationDetailTypeConsent>()
                .Single(x => x.AuthorizationDetailType.Name == authorizationDetail.Type);

            // TODO fix and use the Raw property of the AuthorizationDetailDto
            var rawAuthorizationDetail = JsonSerializer.Serialize(authorizationDetail);
            var authorizationGrantAuthorizationDetailTypeConsent = new AuthorizationGrantAuthorizationDetailTypeConsent(authorizationDetailTypeConsent, authorizationGrant, rawAuthorizationDetail);
            authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantAuthorizationDetailTypeConsent);
        }
    }

    private async Task<AuthorizationGrant> GetAuthorizationGrant(string authorizationGrantId, CancellationToken cancellationToken)
    {
        return await _identityContext
            .Set<AuthorizationGrant>()
            .Where(x => x.Id == authorizationGrantId)
            .Include(x => x.AuthorizationGrantConsents)
            .ThenInclude(x => x.Consent)
            .Include(x => x.Client)
            .Include(x => x.Session)
            .ThenInclude(x => x.SubjectIdentifier)
            .SingleAsync(cancellationToken);
    }
}