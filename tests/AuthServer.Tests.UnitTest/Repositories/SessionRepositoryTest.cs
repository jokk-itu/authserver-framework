﻿using AuthServer.Constants;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Repositories.Abstractions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Repositories;
public class SessionRepositoryTest : BaseUnitTest
{
    public SessionRepositoryTest(ITestOutputHelper outputHelper) : base(outputHelper)
    {
    }

    [Fact]
    public async Task RevokeSession_SessionWithActiveAndInactiveGrantsAndTokens_ExpectSessionAndActiveGrantsAndActiveTokensAreRevoked()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var sessionRepository = serviceProvider.GetRequiredService<ISessionRepository>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var activeAuthorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);

        var revokedAuthorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);
        revokedAuthorizationGrant.Revoke();

        var activeGrantAccessToken = new GrantAccessToken(
            activeAuthorizationGrant,
            DiscoveryDocument.Issuer,
            DiscoveryDocument.Issuer,
            ScopeConstants.UserInfo,
            3600, null);

        var inactiveGrantAccessToken = new GrantAccessToken(
            activeAuthorizationGrant,
            DiscoveryDocument.Issuer,
            DiscoveryDocument.Issuer,
            ScopeConstants.UserInfo,
            -3600, null);

        var revokedGrantAccessToken = new GrantAccessToken(
            activeAuthorizationGrant,
            DiscoveryDocument.Issuer,
            DiscoveryDocument.Issuer,
            ScopeConstants.UserInfo,
            3600, null);

        revokedGrantAccessToken.Revoke();

        await AddEntity(activeGrantAccessToken);
        await AddEntity(inactiveGrantAccessToken);
        await AddEntity(revokedGrantAccessToken);
        await AddEntity(revokedAuthorizationGrant);

        // Act
        await sessionRepository.RevokeSession(session.Id, CancellationToken.None);
        await SaveChangesAsync();

        // Assert
        Assert.NotNull(session.RevokedAt);

        var activeAuthorizationGrantRevocationDate = await IdentityContext
            .Set<AuthorizationGrant>()
            .Where(x => x.Id == activeAuthorizationGrant.Id)
            .Select(x => x.RevokedAt)
            .SingleAsync();

        Assert.NotNull(activeAuthorizationGrantRevocationDate);

        var revokedAuthorizationGrantRevocationDate = await IdentityContext
            .Set<AuthorizationGrant>()
            .Where(x => x.Id == revokedAuthorizationGrant.Id)
            .Select(x => x.RevokedAt)
            .SingleAsync();

        Assert.Equal(revokedAuthorizationGrant.RevokedAt, revokedAuthorizationGrantRevocationDate);

        var revokedTokenRevocationDate = await IdentityContext
            .Set<GrantAccessToken>()
            .Where(x => x.Id == revokedGrantAccessToken.Id)
            .Select(x => x.RevokedAt)
            .SingleAsync();

        Assert.Equal(revokedGrantAccessToken.RevokedAt, revokedTokenRevocationDate);

        var inactiveGrantAccessTokenRevocationDate = await IdentityContext
            .Set<GrantAccessToken>()
            .Where(x => x.Id == inactiveGrantAccessToken.Id)
            .Select(x => x.RevokedAt)
            .SingleAsync();

        Assert.Null(inactiveGrantAccessTokenRevocationDate);

        var activeTokenRevocationDate = await IdentityContext
            .Set<GrantAccessToken>()
            .Where(x => x.Id == activeGrantAccessToken.Id)
            .Select(x => x.RevokedAt)
            .SingleAsync();

        Assert.NotNull(activeTokenRevocationDate);
    }

    [Fact]
    public async Task RevokeExpiredSessions_ExpiredAndActiveSessions_ExpectDeletedExpiredSessions()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var sessionRepository = serviceProvider.GetRequiredService<ISessionRepository>();

        var subjectIdentifier = new SubjectIdentifier();
        var activeSession = new Session(subjectIdentifier);

        var expiredSession = new Session(subjectIdentifier);
        expiredSession.Revoke();

        await AddEntity(activeSession);
        await AddEntity(expiredSession);

        // Act
        await sessionRepository.RevokeExpiredSessions(2, CancellationToken.None);
        await SaveChangesAsync();

        // Assert
        Assert.Null(await IdentityContext.Set<Session>().FirstOrDefaultAsync(x => x.Id == expiredSession.Id));
        Assert.NotNull(await IdentityContext.Set<Session>().FirstOrDefaultAsync(x => x.Id == activeSession.Id));
    }
}
