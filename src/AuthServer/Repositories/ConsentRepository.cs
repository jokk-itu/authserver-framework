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
    public async Task CreateGrantConsent(string authorizationGrantId, IReadOnlyCollection<string> scopes, IReadOnlyCollection<string> resources, CancellationToken cancellationToken)
    {
        var authorizationGrant = await GetAuthorizationGrant(authorizationGrantId, cancellationToken);
        await UpdateConsent(authorizationGrant, scopes, resources, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task MergeGrantConsent(string authorizationGrantId, IReadOnlyCollection<string> scopes, IReadOnlyCollection<string> resources, CancellationToken cancellationToken)
    {
        var authorizationGrant = await GetAuthorizationGrant(authorizationGrantId, cancellationToken);
        await UpdateConsent(authorizationGrant, scopes, resources, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task ReplaceGrantConsent(string authorizationGrantId, IReadOnlyCollection<string> scopes, IReadOnlyCollection<string> resources, CancellationToken cancellationToken)
    {
        var authorizationGrant = await GetAuthorizationGrant(authorizationGrantId, cancellationToken);

        authorizationGrant.AuthorizationGrantConsents.Clear();
        await _identityContext.SaveChangesAsync(cancellationToken);

        await UpdateConsent(authorizationGrant, scopes, resources, cancellationToken);
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
    public async Task<IReadOnlyCollection<Consent>> GetClientConsents(string subjectIdentifier, string clientId, CancellationToken cancellationToken)
    {
        return await _identityContext
            .Set<Consent>()
            .Where(x => x.Client.Id == clientId)
            .Where(x => x.SubjectIdentifier.Id == subjectIdentifier)
            .Include(x => ((ScopeConsent)x).Scope)
            .Include(x => ((ClaimConsent)x).Claim)
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
    public async Task CreateOrUpdateClientConsent(string subjectIdentifier, string clientId, IReadOnlyCollection<string> scopes, IReadOnlyCollection<string> claims, CancellationToken cancellationToken)
    {
        var clientConsents = await _identityContext
            .Set<Consent>()
            .Where(x => x.SubjectIdentifier.Id == subjectIdentifier)
            .Where(x => x.Client.Id == clientId)
            .Include(x => ((ScopeConsent)x).Scope)
            .Include(x => ((ClaimConsent)x).Claim)
            .ToListAsync(cancellationToken);

        var subject = (await _identityContext.FindAsync<SubjectIdentifier>([subjectIdentifier], cancellationToken))!;
        var client = (await _identityContext.FindAsync<Client>([clientId], cancellationToken))!;

        var scopeToAdd = scopes
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

        claims = claims.ToList();
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

    private async Task UpdateConsent(AuthorizationGrant authorizationGrant, IReadOnlyCollection<string> scopes, IReadOnlyCollection<string> resources, CancellationToken cancellationToken)
    {
        var clientConsents = await _identityContext
            .Set<Consent>()
            .Where(x => x.SubjectIdentifier.Id == authorizationGrant.Session.SubjectIdentifier.Id)
            .Where(x => x.Client.Id == authorizationGrant.Client.Id)
            .Include(x => ((ScopeConsent)x).Scope)
            .Include(x => ((ClaimConsent)x).Claim)
            .ToListAsync(cancellationToken);

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
                    authorizationGrantScopeConsent ??= new AuthorizationGrantScopeConsent(scopeConsent, authorizationGrant, resource);
                    authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantScopeConsent);
                }
            }
        }

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