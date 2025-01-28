using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Repositories.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.Repositories;
internal class ConsentGrantRepository : IConsentGrantRepository
{
    private readonly AuthorizationDbContext _identityContext;

    public ConsentGrantRepository(AuthorizationDbContext identityContext)
    {
        _identityContext = identityContext;
    }

    /// <inheritdoc/>
    public async Task CreateConsent(string authorizationGrantId, IEnumerable<string> scopes, IEnumerable<string> claims, CancellationToken cancellationToken)
    {
        var authorizationGrant = await GetAuthorizationGrant(authorizationGrantId, cancellationToken);

        var clientConsents = await GetClientConsentedClaims(authorizationGrant.Session.SubjectIdentifier.Id, authorizationGrant.Client.Id, cancellationToken);
        var consentToRemove = clientConsents
            .Where(x => !claims.Contains(x))
            .ToList();

        _identityContext.RemoveRange(consentToRemove);
        await _identityContext.SaveChangesAsync(cancellationToken);

        await UpdateConsent(authorizationGrant, scopes, claims, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task MergeConsent(string authorizationGrantId, IEnumerable<string> scopes, IEnumerable<string> claims, CancellationToken cancellationToken)
    {
        var authorizationGrant = await GetAuthorizationGrant(authorizationGrantId, cancellationToken);
        await UpdateConsent(authorizationGrant, scopes, claims, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task ReplaceConsent(string authorizationGrantId, IEnumerable<string> scopes, IEnumerable<string> claims, CancellationToken cancellationToken)
    {
        var authorizationGrant = await GetAuthorizationGrant(authorizationGrantId, cancellationToken);

        authorizationGrant.AuthorizationGrantConsents.Clear();
        await _identityContext.SaveChangesAsync(cancellationToken);

        await UpdateConsent(authorizationGrant, scopes, claims, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<IReadOnlyCollection<string>> GetClientConsentedScope(string subjectIdentifier, string clientId, CancellationToken cancellationToken)
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
    public async Task CreateOrUpdateClientConsent(string subjectIdentifier, string clientId, IEnumerable<string> scopes, IEnumerable<string> claims, CancellationToken cancellationToken)
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

    private async Task UpdateConsent(AuthorizationGrant authorizationGrant, IEnumerable<string> scopes, IEnumerable<string> claims, CancellationToken cancellationToken)
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

            var authorizationGrantScopeConsent = authorizationGrant.AuthorizationGrantConsents
                .OfType<AuthorizationGrantScopeConsent>()
                .SingleOrDefault(x => (x.Consent as ScopeConsent)!.Scope.Name == scope);

            if (authorizationGrantScopeConsent is null)
            {
                authorizationGrantScopeConsent ??= new AuthorizationGrantScopeConsent(scopeConsent, authorizationGrant);
                authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantScopeConsent);
            }
        }

        foreach (var claim in claims)
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