﻿using System.Runtime.CompilerServices;
using AuthServer.Constants;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Helpers;
using AuthServer.Repositories.Abstractions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Repositories;
public class AuthorizationGrantRepositoryTest : BaseUnitTest
{
    public AuthorizationGrantRepositoryTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task IsActiveAuthorizationGrant_ActiveGrant_ExpectTrue()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationGrantRepository = serviceProvider.GetRequiredService<IAuthorizationGrantRepository>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var authenticationContextReference = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, authenticationContextReference);
        await AddEntity(authorizationGrant);

        // Act
        var isActive = await authorizationGrantRepository.IsActiveAuthorizationGrant(authorizationGrant.Id, client.Id, CancellationToken.None);

        // Assert
        Assert.True(isActive);
    }

    [Fact]
    public async Task IsActiveAuthorizationGrant_RevokedGrant_ExpectFalse()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationGrantRepository = serviceProvider.GetRequiredService<IAuthorizationGrantRepository>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var authenticationContextReference = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, authenticationContextReference);
        authorizationGrant.Revoke();
        await AddEntity(authorizationGrant);

        // Act
        var isActive = await authorizationGrantRepository.IsActiveAuthorizationGrant(authorizationGrant.Id, client.Id, CancellationToken.None);

        // Assert
        Assert.False(isActive);
    }

    [Fact]
    public async Task UpdateAuthorizationGrant_GrantWithTokens_ExpectUpdatedGrantWithRevokedTokens()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationGrantRepository = serviceProvider.GetRequiredService<IAuthorizationGrantRepository>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var authenticationContextReference = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authenticationMethodReference = await GetAuthenticationMethodReference(AuthenticationMethodReferenceConstants.Password);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, authenticationContextReference);
        var originalAuthTime = DateTime.UtcNow.AddSeconds(-180);
        typeof(AuthorizationGrant)
            .GetProperty(nameof(AuthorizationGrant.UpdatedAuthTime))!
            .SetValue(authorizationGrant, originalAuthTime);

        authorizationGrant.AuthenticationMethodReferences.Add(authenticationMethodReference);
        var grantAccessToken = new GrantAccessToken(authorizationGrant, "aud", "iss", ScopeConstants.UserInfo, 300, null);
        await AddEntity(grantAccessToken);

        // Act
        await authorizationGrantRepository.UpdateAuthorizationGrant(
            authorizationGrant.Id,
            LevelOfAssuranceSubstantial,
            [AuthenticationMethodReferenceConstants.OneTimePassword],
            CancellationToken.None);

        // Assert
        Assert.True(authorizationGrant.UpdatedAuthTime > originalAuthTime);
        Assert.Equal(LevelOfAssuranceSubstantial, authorizationGrant.AuthenticationContextReference.Name);
        Assert.Single(authorizationGrant.AuthenticationMethodReferences);
        Assert.Single(authorizationGrant.AuthenticationMethodReferences,
            x => x.Name == AuthenticationMethodReferenceConstants.OneTimePassword);

        var revokedAt = await IdentityContext
            .Set<GrantAccessToken>()
            .Where(x => x.Id == grantAccessToken.Id)
            .Select(x => x.RevokedAt)
            .SingleAsync();

        Assert.NotNull(revokedAt);
    }

    [Fact]
    public async Task CreateAuthorizationCodeGrant_ActiveSessionWithPasswordAmr_ExpectGrant()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationGrantRepository = serviceProvider.GetRequiredService<IAuthorizationGrantRepository>();
        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("webapp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            SubjectType = SubjectType.Public
        };
        await AddEntity(session);
        await AddEntity(client);

        // Act
        var authorizationGrant = await authorizationGrantRepository.CreateAuthorizationCodeGrant(
            subjectIdentifier.Id,
            client.Id,
            LevelOfAssuranceLow,
            [AuthenticationMethodReferenceConstants.Password],
            CancellationToken.None);

        // Assert
        Assert.Equal(client, authorizationGrant.Client);
        Assert.Equal(session, authorizationGrant.Session);
        Assert.Equal(subjectIdentifier.Id, authorizationGrant.Subject);
        Assert.Single(authorizationGrant.AuthenticationMethodReferences);
        Assert.Equal(AuthenticationMethodReferenceConstants.Password, authorizationGrant.AuthenticationMethodReferences.Single().Name);
    }

    [Fact]
    public async Task CreateAuthorizationCodeGrant_SubjectTypePairwise_ExpectGrant()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationGrantRepository = serviceProvider.GetRequiredService<IAuthorizationGrantRepository>();
        var subjectIdentifier = new SubjectIdentifier();
        var sectorIdentifier = new SectorIdentifier("https://sector.authserver.dk/uris.json");
        var client = new Client("webapp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            SubjectType = SubjectType.Pairwise,
            SectorIdentifier = sectorIdentifier
        };
        await AddEntity(subjectIdentifier);
        await AddEntity(client);

        // Act
        var authorizationGrant = await authorizationGrantRepository.CreateAuthorizationCodeGrant(
            subjectIdentifier.Id,
            client.Id,
            LevelOfAssuranceLow,
            [],
            CancellationToken.None);

        // Assert
        Assert.Equal(client, authorizationGrant.Client);
        Assert.NotNull(authorizationGrant.Session);
        Assert.Equal(PairwiseSubjectHelper.GenerateSubject(sectorIdentifier, subjectIdentifier.Id), authorizationGrant.Subject);
    }

    [Fact]
    public async Task CreateDeviceCodeGrant_ActiveSessionWithPasswordAmr_ExpectGrant()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationGrantRepository = serviceProvider.GetRequiredService<IAuthorizationGrantRepository>();
        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("webapp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            SubjectType = SubjectType.Public
        };
        await AddEntity(session);
        await AddEntity(client);

        // Act
        var authorizationGrant = await authorizationGrantRepository.CreateDeviceCodeGrant(
            subjectIdentifier.Id,
            client.Id,
            LevelOfAssuranceLow,
            [AuthenticationMethodReferenceConstants.Password],
            CancellationToken.None);

        // Assert
        Assert.Equal(client, authorizationGrant.Client);
        Assert.Equal(session, authorizationGrant.Session);
        Assert.Equal(subjectIdentifier.Id, authorizationGrant.Subject);
        Assert.Single(authorizationGrant.AuthenticationMethodReferences);
        Assert.Equal(AuthenticationMethodReferenceConstants.Password, authorizationGrant.AuthenticationMethodReferences.Single().Name);
    }

    [Fact]
    public async Task CreateDeviceCodeGrant_SubjectTypePairwise_ExpectGrant()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationGrantRepository = serviceProvider.GetRequiredService<IAuthorizationGrantRepository>();
        var subjectIdentifier = new SubjectIdentifier();
        var sectorIdentifier = new SectorIdentifier("https://sector.authserver.dk/uris.json");
        var client = new Client("webapp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            SubjectType = SubjectType.Pairwise,
            SectorIdentifier = sectorIdentifier
        };
        await AddEntity(subjectIdentifier);
        await AddEntity(client);

        // Act
        var authorizationGrant = await authorizationGrantRepository.CreateDeviceCodeGrant(
            subjectIdentifier.Id,
            client.Id,
            LevelOfAssuranceLow,
            [],
            CancellationToken.None);

        // Assert
        Assert.Equal(client, authorizationGrant.Client);
        Assert.NotNull(authorizationGrant.Session);
        Assert.Equal(PairwiseSubjectHelper.GenerateSubject(sectorIdentifier, subjectIdentifier.Id), authorizationGrant.Subject);
    }

    [Fact]
    public async Task GetActiveAuthorizationCodeGrant_GrantIdWithRevokedGrant_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationGrantRepository = serviceProvider.GetRequiredService<IAuthorizationGrantRepository>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("webapp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, lowAcr);
        authorizationGrant.Revoke();
        await AddEntity(authorizationGrant);

        // Act
        var activeGrant = await authorizationGrantRepository.GetActiveAuthorizationCodeGrant(authorizationGrant.Id, CancellationToken.None);

        // Assert
        Assert.Null(activeGrant);
    }

    [Fact]
    public async Task GetActiveAuthorizationCodeGrant_GrantIdWithRevokedSession_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationGrantRepository = serviceProvider.GetRequiredService<IAuthorizationGrantRepository>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        session.Revoke();

        var client = new Client("webapp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, lowAcr);
        await AddEntity(authorizationGrant);

        // Act
        var activeGrant = await authorizationGrantRepository.GetActiveAuthorizationCodeGrant(authorizationGrant.Id, CancellationToken.None);
        // Assert
        Assert.Null(activeGrant);
    }

    [Fact]
    public async Task GetActiveAuthorizationCodeGrant_ActiveAuthorizationGrant_ExpectAuthorizationGrant()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationGrantRepository = serviceProvider.GetRequiredService<IAuthorizationGrantRepository>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("webapp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, lowAcr);
        await AddEntity(authorizationGrant);

        // Act
        var activeGrant = await authorizationGrantRepository.GetActiveAuthorizationCodeGrant(authorizationGrant.Id, CancellationToken.None);

        // Assert
        Assert.Equal(authorizationGrant, activeGrant);
    }

    [Fact]
    public async Task RevokeGrant_GrantWithActiveAndInactiveTokens_ExpectGrantIsRevokedAndActiveTokensAreRevoked()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationGrantRepository = serviceProvider.GetRequiredService<IAuthorizationGrantRepository>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);

        var activeGrantAccessToken = new GrantAccessToken(
            authorizationGrant,
            DiscoveryDocument.Issuer,
            DiscoveryDocument.Issuer,
            ScopeConstants.UserInfo,
            3600,
            null);

        var inactiveGrantAccessToken = new GrantAccessToken(
            authorizationGrant,
            DiscoveryDocument.Issuer,
            DiscoveryDocument.Issuer,
            ScopeConstants.UserInfo,
            -3600,
            null);

        var revokedGrantAccessToken = new GrantAccessToken(
            authorizationGrant,
            DiscoveryDocument.Issuer,
            DiscoveryDocument.Issuer,
            ScopeConstants.UserInfo,
            3600,
            null);
        
        revokedGrantAccessToken.Revoke();

        await AddEntity(activeGrantAccessToken);
        await AddEntity(inactiveGrantAccessToken);
        await AddEntity(revokedGrantAccessToken);

        // Act
        await authorizationGrantRepository.RevokeGrant(authorizationGrant.Id, CancellationToken.None);
        await SaveChangesAsync();

        // Assert
        Assert.NotNull(authorizationGrant.RevokedAt);

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
    public async Task RevokeExpiredGrants_ExpiredAndActiveGrants_ExpectDeletedExpiredGrants()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationGrantRepository = serviceProvider.GetRequiredService<IAuthorizationGrantRepository>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var activeAuthorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);

        var expiredAuthorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);
        expiredAuthorizationGrant.Revoke();

        await AddEntity(activeAuthorizationGrant);
        await AddEntity(expiredAuthorizationGrant);

        // Act
        await authorizationGrantRepository.RevokeExpiredGrants(2, CancellationToken.None);
        await SaveChangesAsync();

        // Assert
        Assert.Null(await IdentityContext.Set<AuthorizationGrant>().FirstOrDefaultAsync(x => x.Id == expiredAuthorizationGrant.Id));
        Assert.NotNull(await IdentityContext.Set<AuthorizationGrant>().FirstOrDefaultAsync(x => x.Id == activeAuthorizationGrant.Id));
    }
}
