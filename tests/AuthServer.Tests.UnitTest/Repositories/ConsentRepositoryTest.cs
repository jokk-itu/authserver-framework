using AuthServer.Constants;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Repositories.Abstractions;
using AuthServer.Repositories.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Repositories;

public class ConsentRepositoryTest(ITestOutputHelper outputHelper) : BaseUnitTest(outputHelper)
{
    [Fact]
    public async Task GetGrantConsentedScopes_TwoGrantsWithGrantConsentedScope_ExpectOneGrantConsentedScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var consentRepository = serviceProvider.GetRequiredService<IConsentRepository>();

        var authorizationGrant = await GetAuthorizationGrant(
            ScopeConstants.OpenId,
            "https://weather.authserver.dk",
            ClaimNameConstants.Name);

        await GetAuthorizationGrant(
            ScopeConstants.Profile,
            "https://idp.authserver.dk",
            ClaimNameConstants.Address);

        // Act
        var grantConsentedScopes = await consentRepository.GetGrantConsentedScopes(authorizationGrant.Id, CancellationToken.None);

        // Assert
        Assert.Single(grantConsentedScopes);

        var scopeDto = grantConsentedScopes.Single();
        Assert.Equal(ScopeConstants.OpenId, scopeDto.Name);
        Assert.Equal("https://weather.authserver.dk", scopeDto.Resource);
    }

    [Fact]
    public async Task GetGrantConsentedClaims_TwoGrantsWithGrantConsentedClaims_ExpectOneGrantConsentedClaim()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var consentRepository = serviceProvider.GetRequiredService<IConsentRepository>();

        var authorizationGrant = await GetAuthorizationGrant(
            ScopeConstants.OpenId,
            "https://weather.authserver.dk",
            ClaimNameConstants.Name);

        await GetAuthorizationGrant(
            ScopeConstants.Profile,
            "https://idp.authserver.dk",
            ClaimNameConstants.Address);

        // Act
        var grantConsentedClaims = await consentRepository.GetGrantConsentedClaims(authorizationGrant.Id, CancellationToken.None);

        // Assert
        Assert.Single(grantConsentedClaims);
        Assert.Equal(ClaimNameConstants.Name, grantConsentedClaims.Single());
    }

    [Fact]
    public async Task GetGrantConsents_TwoGrantsWithGrantConsents_ExpectConsentsFromOneGrant()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var consentRepository = serviceProvider.GetRequiredService<IConsentRepository>();

        var authorizationGrant = await GetAuthorizationGrant(
            ScopeConstants.OpenId,
            "https://weather.authserver.dk",
            ClaimNameConstants.Name);

        await GetAuthorizationGrant(
            ScopeConstants.Profile,
            "https://idp.authserver.dk",
            ClaimNameConstants.Address);

        // Act
        var grantConsents = await consentRepository.GetGrantConsents(authorizationGrant.Id, CancellationToken.None);

        // Assert
        Assert.Equal(2, grantConsents.Count);

        var claimQuery = grantConsents.OfType<AuthorizationGrantClaimConsent>().ToList();
        Assert.Single(claimQuery);
        var authorizationGrantClaimConsent = claimQuery.Single();
        var claimConsent = (authorizationGrantClaimConsent.Consent as ClaimConsent)!;
        Assert.Equal(ClaimNameConstants.Name, claimConsent.Claim.Name);

        var scopeQuery = grantConsents.OfType<AuthorizationGrantScopeConsent>().ToList();
        Assert.Single(scopeQuery);
        var authorizationGrantScopeConsent = scopeQuery.Single();
        Assert.Equal("https://weather.authserver.dk", authorizationGrantScopeConsent.Resource);

        var scopeConsent = (authorizationGrantScopeConsent.Consent as ScopeConsent)!;
        Assert.Equal(ScopeConstants.OpenId, scopeConsent.Scope.Name);
    }

    [Fact]
    public async Task GetClientConsentedScopes_TwoClientConsentedScopes_ExpectOneClientConsentedScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var consentRepository = serviceProvider.GetRequiredService<IConsentRepository>();

        var (subjectIdentifier, clientId) = await GetClientConsent(ScopeConstants.OpenId, ClaimNameConstants.Name);
        await GetClientConsent(ScopeConstants.Profile, ClaimNameConstants.Address);

        // Act
        var clientConsents = await consentRepository.GetClientConsentedScopes(subjectIdentifier, clientId, CancellationToken.None);

        // Assert
        Assert.Single(clientConsents);
        var scopeConsent = clientConsents.Single();
        Assert.Equal(ScopeConstants.OpenId, scopeConsent);
    }

    [Fact]
    public async Task GetClientConsentedClaims_TwoClientConsentedClaims_ExpectOneClientConsentedClaim()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var consentRepository = serviceProvider.GetRequiredService<IConsentRepository>();

        var (subjectIdentifier, clientId) = await GetClientConsent(ScopeConstants.OpenId, ClaimNameConstants.Name);
        await GetClientConsent(ScopeConstants.Profile, ClaimNameConstants.Address);

        // Act
        var clientConsents = await consentRepository.GetClientConsentedClaims(subjectIdentifier, clientId, CancellationToken.None);

        // Assert
        Assert.Single(clientConsents);
        var claimConsent = clientConsents.Single();
        Assert.Equal(ClaimNameConstants.Name, claimConsent);
    }

    [Fact]
    public async Task GetClientConsents_TwoClientConsents_ExpectTwoClientConsents()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var consentRepository = serviceProvider.GetRequiredService<IConsentRepository>();

        var (subjectIdentifier, clientId) = await GetClientConsent(ScopeConstants.OpenId, ClaimNameConstants.Name);
        await GetClientConsent(ScopeConstants.Profile, ClaimNameConstants.Address);

        // Act
        var clientConsents = await consentRepository.GetClientConsents(subjectIdentifier, clientId, CancellationToken.None);

        // Assert
        Assert.Equal(2, clientConsents.Count);

        var scopeConsents = clientConsents.OfType<ScopeConsent>().ToList();
        Assert.Single(scopeConsents);
        var scopeConsent = scopeConsents.Single();
        Assert.Equal(ScopeConstants.OpenId, scopeConsent.Scope.Name);

        var claimQuery = clientConsents.OfType<ClaimConsent>().ToList();
        Assert.Single(claimQuery);
        var claimConsent = claimQuery.Single();
        Assert.Equal(ClaimNameConstants.Name, claimConsent.Claim.Name);
    }

    [Fact]
    public async Task CreateOrUpdateClientConsent_NoExistingConsent_ExpectCreateClientConsent()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var consentRepository = serviceProvider.GetRequiredService<IConsentRepository>();

        var subjectIdentifier = new SubjectIdentifier();
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        await AddEntity(subjectIdentifier);
        await AddEntity(client);

        // Act
        await consentRepository.CreateOrUpdateClientConsent(
            subjectIdentifier.Id,
            client.Id,
            [ScopeConstants.OpenId],
            [ClaimNameConstants.Name],
            CancellationToken.None);

        // Assert
        var consents = await IdentityContext
            .Set<Consent>()
            .Where(x => x.SubjectIdentifier.Id == subjectIdentifier.Id)
            .Where(x => x.Client.Id == client.Id)
            .ToListAsync();

        Assert.Equal(2, consents.Count);

        var scopeConsents = consents.OfType<ScopeConsent>().ToList();
        Assert.Single(scopeConsents);
        var scopeConsent = scopeConsents.Single();
        Assert.Equal(ScopeConstants.OpenId, scopeConsent.Scope.Name);

        var claimConsents = consents.OfType<ClaimConsent>().ToList();
        Assert.Single(claimConsents);
        var claimConsent = claimConsents.Single();
        Assert.Equal(ClaimNameConstants.Name, claimConsent.Claim.Name);
    }

    [Fact]
    public async Task CreateOrUpdateClientConsent_ExistingConsent_ExpectUpdateClientConsent()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var consentRepository = serviceProvider.GetRequiredService<IConsentRepository>();

        var subjectIdentifier = new SubjectIdentifier();
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        await AddEntity(new ScopeConsent(subjectIdentifier, client, await GetScope(ScopeConstants.Profile)));
        await AddEntity(new ClaimConsent(subjectIdentifier, client, await GetClaim(ClaimNameConstants.Birthdate)));

        // Act
        await consentRepository.CreateOrUpdateClientConsent(
            subjectIdentifier.Id,
            client.Id,
            [ScopeConstants.OpenId],
            [ClaimNameConstants.Name],
            CancellationToken.None);

        // Assert
        var consents = await IdentityContext
            .Set<Consent>()
            .Where(x => x.SubjectIdentifier.Id == subjectIdentifier.Id)
            .Where(x => x.Client.Id == client.Id)
            .ToListAsync();

        Assert.Equal(3, consents.Count);

        Assert.Collection(
            consents.OfType<ScopeConsent>(),
            sc => Assert.Equal(ScopeConstants.Profile, sc.Scope.Name),
            sc => Assert.Equal(ScopeConstants.OpenId, sc.Scope.Name)
        );

        var claimConsents = consents.OfType<ClaimConsent>().ToList();
        Assert.Single(claimConsents);
        Assert.Equal(ClaimNameConstants.Name, claimConsents.Single().Claim.Name);
    }

    [Fact]
    public async Task CreateGrantConsent_WithClientConsents_ExpectGrantConsentCreated()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var consentRepository = serviceProvider.GetRequiredService<IConsentRepository>();

        var authorizationGrant = await GetAuthorizationGrant(
            ScopeConstants.Profile, "https://idp.authserver.dk", ClaimNameConstants.Name);

        authorizationGrant.AuthorizationGrantConsents.Clear();

        var idpClient = new Client("idp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic)
        {
            ClientUri = "https://idp.authserver.dk"
        };
        idpClient.Scopes.Add(await GetScope(ScopeConstants.Profile));
        await AddEntity(idpClient);

        // Act
        await consentRepository.CreateGrantConsent(
            authorizationGrant.Id,
            [ScopeConstants.Profile],
            ["https://idp.authserver.dk"],
            CancellationToken.None);

        // Assert
        var scopeDtos = authorizationGrant.AuthorizationGrantConsents
            .OfType<AuthorizationGrantScopeConsent>()
            .Select(x => new ScopeDto(((ScopeConsent)x.Consent).Scope.Name, x.Resource))
            .ToList();

        Assert.Single(scopeDtos);
        Assert.Single(scopeDtos, x => x is { Name: ScopeConstants.Profile, Resource: "https://idp.authserver.dk" });

        var claims = authorizationGrant.AuthorizationGrantConsents
            .OfType<AuthorizationGrantClaimConsent>()
            .Select(x => x.Consent)
            .OfType<ClaimConsent>()
            .Select(x => x.Claim.Name)
            .ToList();

        Assert.Single(claims);
        Assert.Single(claims, ClaimNameConstants.Name);
    }

    [Fact]
    public async Task MergeGrantConsent_WithGrantConsents_ExpectGrantConsentMerged()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var consentRepository = serviceProvider.GetRequiredService<IConsentRepository>();

        var authorizationGrant = await GetAuthorizationGrant(
            ScopeConstants.UserInfo, "https://idp.authserver.dk", ClaimNameConstants.Name);

        var scopeConsent = new ScopeConsent(
            authorizationGrant.Session.SubjectIdentifier,
            authorizationGrant.Client,
            await GetScope(ScopeConstants.Profile));

        await AddEntity(scopeConsent);

        var claimConsent = new ClaimConsent(
            authorizationGrant.Session.SubjectIdentifier,
            authorizationGrant.Client,
            await GetClaim(ClaimNameConstants.FamilyName));

        await AddEntity(claimConsent);

        var idpClient = new Client("idp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic)
        {
            ClientUri = "https://idp.authserver.dk"
        };
        idpClient.Scopes.Add(await GetScope(ScopeConstants.UserInfo));
        idpClient.Scopes.Add(await GetScope(ScopeConstants.Profile));
        await AddEntity(idpClient);

        var weatherClient = new Client("weather", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic)
        {
            ClientUri = "https://weather.authserver.dk"
        };
        weatherClient.Scopes.Add(await GetScope(ScopeConstants.UserInfo));
        await AddEntity(weatherClient);

        // Act
        await consentRepository.MergeGrantConsent(
            authorizationGrant.Id,
            [ScopeConstants.UserInfo, ScopeConstants.Profile],
            ["https://idp.authserver.dk", "https://weather.authserver.dk"],
            CancellationToken.None);

        // Assert
        var scopeDtos = authorizationGrant.AuthorizationGrantConsents
            .OfType<AuthorizationGrantScopeConsent>()
            .Select(x => new ScopeDto(((ScopeConsent)x.Consent).Scope.Name, x.Resource))
            .ToList();

        Assert.Single(scopeDtos, x => x is { Name: ScopeConstants.UserInfo, Resource: "https://idp.authserver.dk" });
        Assert.Single(scopeDtos, x => x is { Name: ScopeConstants.UserInfo, Resource: "https://weather.authserver.dk" });
        Assert.Single(scopeDtos, x => x is { Name: ScopeConstants.Profile, Resource: "https://idp.authserver.dk" });
        Assert.DoesNotContain(scopeDtos, x => x is { Name: ScopeConstants.Profile, Resource: "https://weather.authserver.dk" });

        var claims = authorizationGrant.AuthorizationGrantConsents
            .OfType<AuthorizationGrantClaimConsent>()
            .Select(x => x.Consent)
            .OfType<ClaimConsent>()
            .Select(x => x.Claim.Name)
            .ToList();

        Assert.Equal(2, claims.Count);
        Assert.Single(claims, ClaimNameConstants.Name);
        Assert.Single(claims, ClaimNameConstants.FamilyName);
    }

    [Fact]
    public async Task ReplaceGrantConsent_WithGrantConsents_ExpectGrantConsentReplaced()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var consentRepository = serviceProvider.GetRequiredService<IConsentRepository>();

        var authorizationGrant = await GetAuthorizationGrant(
            ScopeConstants.UserInfo, "https://idp.authserver.dk", ClaimNameConstants.FamilyName);

        var scopeConsent = new ScopeConsent(
            authorizationGrant.Session.SubjectIdentifier,
            authorizationGrant.Client,
            await GetScope(ScopeConstants.Profile));

        await AddEntity(scopeConsent);

        var idpClient = new Client("idp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic)
        {
            ClientUri = "https://idp.authserver.dk"
        };
        idpClient.Scopes.Add(await GetScope(ScopeConstants.Profile));
        idpClient.Scopes.Add(await GetScope(ScopeConstants.UserInfo));
        await AddEntity(idpClient);

        // Act
        await consentRepository.ReplaceGrantConsent(
            authorizationGrant.Id,
            [ScopeConstants.Profile],
            ["https://idp.authserver.dk"],
            CancellationToken.None);

        // Assert
        var scopeDtos = authorizationGrant.AuthorizationGrantConsents
            .OfType<AuthorizationGrantScopeConsent>()
            .Select(x => new ScopeDto(((ScopeConsent)x.Consent).Scope.Name, x.Resource))
            .ToList();

        Assert.Single(scopeDtos);
        Assert.Single(scopeDtos, x => x is { Name: ScopeConstants.Profile, Resource: "https://idp.authserver.dk" });

        var claims = authorizationGrant.AuthorizationGrantConsents
            .OfType<AuthorizationGrantClaimConsent>()
            .Select(x => x.Consent)
            .OfType<ClaimConsent>()
            .Select(x => x.Claim.Name)
            .ToList();

        Assert.Single(claims);
        Assert.Single(claims, ClaimNameConstants.FamilyName);
    }

    private async Task<(string SubjectIdentifier, string ClientId)> GetClientConsent(string scope, string claim)
    {
        var subjectIdentifier = new SubjectIdentifier();
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var scopeConsent = new ScopeConsent(subjectIdentifier, client, await GetScope(scope));
        var claimConsent = new ClaimConsent(subjectIdentifier, client, await GetClaim(claim));

        await AddEntity(scopeConsent);
        await AddEntity(claimConsent);

        return (subjectIdentifier.Id, client.Id);
    }

    private async Task<AuthorizationGrant> GetAuthorizationGrant(string scope, string resource, string claim)
    {
        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var authenticationContextReference = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, authenticationContextReference);

        var scopeConsent = new ScopeConsent(subjectIdentifier, client, await GetScope(scope));
        var authorizationGrantScopeConsent = new AuthorizationGrantScopeConsent(scopeConsent, authorizationGrant, resource);
        authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantScopeConsent);

        var claimConsent = new ClaimConsent(subjectIdentifier, client, await GetClaim(claim));
        var authorizationGrantClaimConsent = new AuthorizationGrantClaimConsent(claimConsent, authorizationGrant);
        authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantClaimConsent);

        await AddEntity(authorizationGrant);
        return authorizationGrant;
    }
}