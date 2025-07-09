﻿using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Helpers;
using AuthServer.Repositories.Abstractions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using System.Diagnostics;

namespace AuthServer.Repositories;

internal class AuthorizationGrantRepository : IAuthorizationGrantRepository
{
    private readonly AuthorizationDbContext _identityContext;
    private readonly ILogger<AuthorizationGrantRepository> _logger;

    public AuthorizationGrantRepository(
        AuthorizationDbContext identityContext,
        ILogger<AuthorizationGrantRepository> logger)
    {
        _identityContext = identityContext;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task<bool> IsActiveAuthorizationGrant(string authorizationGrantId, string clientId, CancellationToken cancellationToken)
    {
        return await _identityContext
            .Set<AuthorizationGrant>()
            .Where(x => x.Id == authorizationGrantId)
            .Where(x => x.Client.Id == clientId)
            .Where(AuthorizationGrant.IsActive)
            .AnyAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task UpdateAuthorizationGrant(
        string authorizationGrantId,
        string authenticationContextReference,
        IReadOnlyCollection<string> authenticationMethodReferences,
        CancellationToken cancellationToken)
    {
        var authorizationGrant = await _identityContext
            .Set<AuthorizationGrant>()
            .Where(x => x.Id == authorizationGrantId)
            .Include(x => x.AuthenticationMethodReferences)
            .SingleAsync(cancellationToken);

        var acr = await GetAuthenticationContextReference(authenticationContextReference, cancellationToken);
        var amr = await GetAuthenticationMethodReferences(authenticationMethodReferences, cancellationToken);

        authorizationGrant.UpdateAuthTime();
        authorizationGrant.AuthenticationContextReference = acr;
        authorizationGrant.AuthenticationMethodReferences.Clear();

        foreach (var reference in amr)
        {
            authorizationGrant.AuthenticationMethodReferences.Add(reference);
        }

        await RevokeTokens(authorizationGrantId, cancellationToken);

        await _identityContext.SaveChangesAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<AuthorizationGrant> CreateAuthorizationGrant(
        string subjectIdentifier,
        string clientId,
        string authenticationContextReference,
        IReadOnlyCollection<string> authenticationMethodReferences,
        CancellationToken cancellationToken)
    {
        var session = await GetSession(subjectIdentifier, cancellationToken);
        var client = (await _identityContext.FindAsync<Client>([clientId], cancellationToken))!;
        var subject = await GetSubject(subjectIdentifier, clientId, cancellationToken);
        var acr = await GetAuthenticationContextReference(authenticationContextReference, cancellationToken);
        var amr = await GetAuthenticationMethodReferences(authenticationMethodReferences, cancellationToken);

        var newGrant = new AuthorizationCodeGrant(session, client, subject, acr)
        {
            AuthenticationMethodReferences = amr
        };
        await _identityContext.AddAsync(newGrant, cancellationToken);
        await _identityContext.SaveChangesAsync(cancellationToken);
        return newGrant;
    }

    /// <inheritdoc/>
    public async Task<AuthorizationCodeGrant?> GetActiveAuthorizationCodeGrant(string authorizationGrantId, CancellationToken cancellationToken)
    {
        return await _identityContext
            .Set<AuthorizationGrant>()
            .Include(x => x.AuthenticationContextReference)
            .Include(x => x.Client)
            .Include(x => x.Session)
            .ThenInclude(x => x.SubjectIdentifier)
            .Where(AuthorizationGrant.IsActive)
            .Where(x => x.Session.RevokedAt == null)
            .Where(x => x.Id == authorizationGrantId)
            .OfType<AuthorizationCodeGrant>()
            .SingleOrDefaultAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task RevokeGrant(string authorizationGrantId, CancellationToken cancellationToken)
    {
        var affectedTokens = await RevokeTokens(authorizationGrantId, cancellationToken);

        var authorizationGrant = (await _identityContext.Set<AuthorizationGrant>().FindAsync([authorizationGrantId], cancellationToken))!;
        authorizationGrant.Revoke();

        _logger.LogInformation(
            "Revoked AuthorizationGrant {AuthorizationGrantId} and Tokens {AffectedTokens}",
            authorizationGrantId,
            affectedTokens);
    }

    /// <inheritdoc/>
    public async Task RevokeExpiredGrants(int batchSize, CancellationToken cancellationToken)
    {
        var timer = Stopwatch.StartNew();

        var affectedGrants = await _identityContext
            .Set<AuthorizationGrant>()
            .Where(AuthorizationGrant.IsExpired)
            .Take(batchSize)
            .ExecuteDeleteAsync(cancellationToken);

        timer.Stop();

        _logger.LogInformation(
            "Revoked {Amount} grants in {ElapsedTime} milliseconds",
            affectedGrants,
            timer.ElapsedMilliseconds);
    }

    private async Task<int> RevokeTokens(string authorizationGrantId, CancellationToken cancellationToken)
    {
        return await _identityContext
            .Set<AuthorizationGrant>()
            .Where(ag => ag.Id == authorizationGrantId)
            .SelectMany(g => g.GrantTokens)
            .Where(Token.IsActive)
            .ExecuteUpdateAsync(
                propertyCall => propertyCall.SetProperty(gt => gt.RevokedAt, DateTime.UtcNow),
                cancellationToken);
    }

    private async Task<List<AuthenticationMethodReference>> GetAuthenticationMethodReferences(IReadOnlyCollection<string> authenticationMethodReferences, CancellationToken cancellationToken)
    {
        return await _identityContext
            .Set<AuthenticationMethodReference>()
            .Where(x => authenticationMethodReferences.Contains(x.Name))
            .ToListAsync(cancellationToken);
    }

    private async Task<AuthenticationContextReference> GetAuthenticationContextReference(string authenticationContextReference, CancellationToken cancellationToken)
    {
        return await _identityContext
            .Set<AuthenticationContextReference>()
            .Where(x => x.Name == authenticationContextReference)
            .SingleAsync(cancellationToken);
    }

    private async Task<Session> GetSession(string subjectIdentifier, CancellationToken cancellationToken)
    {
        var session = await _identityContext
            .Set<Session>()
            .Include(x => x.SubjectIdentifier)
            .Where(x => x.SubjectIdentifier.Id == subjectIdentifier)
            .Where(Session.IsActive)
            .SingleOrDefaultAsync(cancellationToken);

        var publicSubjectIdentifier = (session?.SubjectIdentifier ??
                                       await _identityContext.FindAsync<SubjectIdentifier>([subjectIdentifier],
                                           cancellationToken))!;

        session ??= new Session(publicSubjectIdentifier);
        return session;
    }

    private async Task<string> GetSubject(string subjectIdentifier, string clientId, CancellationToken cancellationToken)
    {
        var client = await _identityContext
            .Set<Client>()
            .Include(x => x.SectorIdentifier)
            .Where(x => x.Id == clientId)
            .SingleAsync(cancellationToken);

        if (client.SubjectType == SubjectType.Public)
        {
            return subjectIdentifier;
        }

        if (client.SubjectType == SubjectType.Pairwise)
        {
            return PairwiseSubjectHelper.GenerateSubject(client.SectorIdentifier!, subjectIdentifier);
        }

        throw new InvalidOperationException("SubjectType has invalid value");
    }
}