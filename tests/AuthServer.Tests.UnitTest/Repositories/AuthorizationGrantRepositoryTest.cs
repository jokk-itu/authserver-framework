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
    public async Task UpdateAuthorizationCodeGrant_GrantWithTokens_ExpectUpdatedGrantWithRevokedTokens()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationGrantRepository = serviceProvider.GetRequiredService<IAuthorizationGrantRepository>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var authenticationContextReference = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authenticationMethodReference = await GetAuthenticationMethodReference(AuthenticationMethodReferenceConstants.Password);
        var authorizationCodeGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, authenticationContextReference);
        var originalAuthTime = DateTime.UtcNow.AddSeconds(-180);
        typeof(AuthorizationGrant)
            .GetProperty(nameof(AuthorizationGrant.UpdatedAuthTime))!
            .SetValue(authorizationCodeGrant, originalAuthTime);

        authorizationCodeGrant.AuthenticationMethodReferences.Add(authenticationMethodReference);
        var grantAccessToken = new GrantAccessToken(authorizationCodeGrant, "aud", "iss", ScopeConstants.UserInfo, 300);
        await AddEntity(grantAccessToken);

        // Act
        await authorizationGrantRepository.UpdateAuthorizationCodeGrant(
            authorizationCodeGrant.Id,
            LevelOfAssuranceSubstantial,
            [AuthenticationMethodReferenceConstants.OneTimePassword],
            CancellationToken.None);

        // Assert
        Assert.True(authorizationCodeGrant.UpdatedAuthTime > originalAuthTime);
        Assert.Equal(LevelOfAssuranceSubstantial, authorizationCodeGrant.AuthenticationContextReference.Name);
        Assert.Single(authorizationCodeGrant.AuthenticationMethodReferences);
        Assert.Single(authorizationCodeGrant.AuthenticationMethodReferences,
            x => x.Name == AuthenticationMethodReferenceConstants.OneTimePassword);

        var revokedAt = await IdentityContext
            .Set<GrantAccessToken>()
            .Where(x => x.Id == grantAccessToken.Id)
            .Select(x => x.RevokedAt)
            .SingleAsync();

        Assert.NotNull(revokedAt);
    }

    [Fact]
    public async Task UpdateDeviceCodeGrant_GrantWithTokens_ExpectUpdatedGrantWithRevokedTokens()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationGrantRepository = serviceProvider.GetRequiredService<IAuthorizationGrantRepository>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var authenticationContextReference = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authenticationMethodReference = await GetAuthenticationMethodReference(AuthenticationMethodReferenceConstants.Password);
        var deviceCodeGrant = new DeviceCodeGrant(session, client, subjectIdentifier.Id, authenticationContextReference);
        var originalAuthTime = DateTime.UtcNow.AddSeconds(-180);
        typeof(AuthorizationGrant)
            .GetProperty(nameof(AuthorizationGrant.UpdatedAuthTime))!
            .SetValue(deviceCodeGrant, originalAuthTime);

        deviceCodeGrant.AuthenticationMethodReferences.Add(authenticationMethodReference);
        var grantAccessToken = new GrantAccessToken(deviceCodeGrant, "aud", "iss", ScopeConstants.UserInfo, 300);
        await AddEntity(grantAccessToken);

        var deviceCode = new DeviceCode(300, 5);
        deviceCode.SetRawValue("raw_value");
        var userCode = new UserCode(deviceCode, CryptographyHelper.GetUserCode());
        await AddEntity(userCode);

        // Act
        await authorizationGrantRepository.UpdateDeviceCodeGrant(
            deviceCodeGrant.Id,
            deviceCode.Id,
            LevelOfAssuranceSubstantial,
            [AuthenticationMethodReferenceConstants.OneTimePassword],
            CancellationToken.None);

        // Assert
        Assert.True(deviceCodeGrant.UpdatedAuthTime > originalAuthTime);
        Assert.Contains(deviceCode, deviceCodeGrant.DeviceCodes);
        Assert.Equal(LevelOfAssuranceSubstantial, deviceCodeGrant.AuthenticationContextReference.Name);
        Assert.Single(deviceCodeGrant.AuthenticationMethodReferences);
        Assert.Single(deviceCodeGrant.AuthenticationMethodReferences,
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
        var deviceCode = new DeviceCode(300, 5);
        deviceCode.SetRawValue("raw_value");
        var userCode = new UserCode(deviceCode, CryptographyHelper.GetUserCode());
        await AddEntity(session);
        await AddEntity(client);
        await AddEntity(userCode);

        // Act
        var authorizationGrant = await authorizationGrantRepository.CreateDeviceCodeGrant(
            subjectIdentifier.Id,
            client.Id,
            deviceCode.Id,
            LevelOfAssuranceLow,
            [AuthenticationMethodReferenceConstants.Password],
            CancellationToken.None);

        // Assert
        Assert.Equal(client, authorizationGrant.Client);
        Assert.Equal(session, authorizationGrant.Session);
        Assert.Equal(subjectIdentifier.Id, authorizationGrant.Subject);
        Assert.Single(authorizationGrant.AuthenticationMethodReferences);
        Assert.Equal(AuthenticationMethodReferenceConstants.Password, authorizationGrant.AuthenticationMethodReferences.Single().Name);
        Assert.Contains(deviceCode, authorizationGrant.DeviceCodes);
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
        var deviceCode = new DeviceCode(300, 5);
        deviceCode.SetRawValue("raw_value");
        var userCode = new UserCode(deviceCode, CryptographyHelper.GetUserCode());
        await AddEntity(subjectIdentifier);
        await AddEntity(client);
        await AddEntity(userCode);

        // Act
        var authorizationGrant = await authorizationGrantRepository.CreateDeviceCodeGrant(
            subjectIdentifier.Id,
            client.Id,
            deviceCode.Id,
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
            3600);

        var inactiveGrantAccessToken = new GrantAccessToken(
            authorizationGrant,
            DiscoveryDocument.Issuer,
            DiscoveryDocument.Issuer,
            ScopeConstants.UserInfo,
            -3600);

        var revokedGrantAccessToken = new GrantAccessToken(
            authorizationGrant,
            DiscoveryDocument.Issuer,
            DiscoveryDocument.Issuer,
            ScopeConstants.UserInfo,
            3600);
        
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
