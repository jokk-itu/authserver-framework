using System.Text.Json;
using AuthServer.Constants;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Repositories.Abstractions;
using AuthServer.Repositories.Models;
using AuthServer.Tests.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SQLitePCL;
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
            ClaimNameConstants.Name,
            AuthorizationDetailTypeConstants.OpenId);

        await GetAuthorizationGrant(
            ScopeConstants.Profile,
            "https://idp.authserver.dk",
            ClaimNameConstants.Address,
            AuthorizationDetailTypeConstants.OpenId);

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
            ClaimNameConstants.Name,
            AuthorizationDetailTypeConstants.OpenId);

        await GetAuthorizationGrant(
            ScopeConstants.Profile,
            "https://idp.authserver.dk",
            ClaimNameConstants.Address,
            AuthorizationDetailTypeConstants.OpenId);

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
            ClaimNameConstants.Name,
            AuthorizationDetailTypeConstants.OpenId);

        await GetAuthorizationGrant(
            ScopeConstants.Profile,
            "https://idp.authserver.dk",
            ClaimNameConstants.Address,
            AuthorizationDetailTypeConstants.OpenId);

        // Act
        var grantConsents = await consentRepository.GetGrantConsents(authorizationGrant.Id, CancellationToken.None);

        // Assert
        Assert.Equal(3, grantConsents.Count);

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

        var (subjectIdentifier, clientId) = await GetClientConsent(ScopeConstants.OpenId, ClaimNameConstants.Name, AuthorizationDetailTypeConstants.OpenId);
        await GetClientConsent(ScopeConstants.Profile, ClaimNameConstants.Address, AuthorizationDetailTypeConstants.Profile);

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

        var (subjectIdentifier, clientId) = await GetClientConsent(ScopeConstants.OpenId, ClaimNameConstants.Name, AuthorizationDetailTypeConstants.OpenId);
        await GetClientConsent(ScopeConstants.Profile, ClaimNameConstants.Address, AuthorizationDetailTypeConstants.Profile);

        // Act
        var clientConsents = await consentRepository.GetClientConsentedClaims(subjectIdentifier, clientId, CancellationToken.None);

        // Assert
        Assert.Single(clientConsents);
        var claimConsent = clientConsents.Single();
        Assert.Equal(ClaimNameConstants.Name, claimConsent);
    }

    [Fact]
    public async Task GetClientConsents_ThreeClientConsents_ExpectThreeClientConsents()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var consentRepository = serviceProvider.GetRequiredService<IConsentRepository>();

        var (subjectIdentifier, clientId) = await GetClientConsent(ScopeConstants.OpenId, ClaimNameConstants.Name, AuthorizationDetailTypeConstants.OpenId);
        await GetClientConsent(ScopeConstants.Profile, ClaimNameConstants.Address, AuthorizationDetailTypeConstants.Profile);

        // Act
        var clientConsents = await consentRepository.GetClientConsents(subjectIdentifier, clientId, CancellationToken.None);

        // Assert
        Assert.Equal(3, clientConsents.Count);

        var scopeConsents = clientConsents.OfType<ScopeConsent>().ToList();
        Assert.Single(scopeConsents);
        var scopeConsent = scopeConsents.Single();
        Assert.Equal(ScopeConstants.OpenId, scopeConsent.Scope.Name);

        var claimQuery = clientConsents.OfType<ClaimConsent>().ToList();
        Assert.Single(claimQuery);
        var claimConsent = claimQuery.Single();
        Assert.Equal(ClaimNameConstants.Name, claimConsent.Claim.Name);

        var authorizationDetailTypeQuery = clientConsents.OfType<AuthorizationDetailTypeConsent>().ToList();
        Assert.Single(authorizationDetailTypeQuery);
        var authorizationDetailTypeConsent = authorizationDetailTypeQuery.Single();
        Assert.Equal(AuthorizationDetailTypeConstants.OpenId, authorizationDetailTypeConsent.AuthorizationDetailType.Name);
    }

    [Fact]
    public async Task CreateOrUpdateClientConsent_NoExistingConsent_ExpectCreateClientConsent()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var consentRepository = serviceProvider.GetRequiredService<IConsentRepository>();

        var subjectIdentifier = new SubjectIdentifier();
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(subjectIdentifier);
        await AddEntity(client);

        // Act
        await consentRepository.CreateOrUpdateClientConsent(
            new ConsentDto
            {
                SubjectIdentifier = subjectIdentifier.Id,
                ClientId = client.Id,
                ConsentedScopes = [ScopeConstants.OpenId],
                ConsentedClaims = [ClaimNameConstants.Name],
                ConsentedAuthorizationDetailTypes = [AuthorizationDetailTypeConstants.OpenId]
            }, 
            CancellationToken.None);

        // Assert
        var consents = await IdentityContext
            .Set<Consent>()
            .Where(x => x.SubjectIdentifier.Id == subjectIdentifier.Id)
            .Where(x => x.Client.Id == client.Id)
            .ToListAsync();

        Assert.Equal(3, consents.Count);

        var scopeConsents = consents.OfType<ScopeConsent>().ToList();
        Assert.Single(scopeConsents);
        var scopeConsent = scopeConsents.Single();
        Assert.Equal(ScopeConstants.OpenId, scopeConsent.Scope.Name);

        var claimConsents = consents.OfType<ClaimConsent>().ToList();
        Assert.Single(claimConsents);
        var claimConsent = claimConsents.Single();
        Assert.Equal(ClaimNameConstants.Name, claimConsent.Claim.Name);

        var authorizationDetailTypeConsents = consents.OfType<AuthorizationDetailTypeConsent>().ToList();
        Assert.Single(authorizationDetailTypeConsents);
        var authorizationDetailTypeConsent = authorizationDetailTypeConsents.Single();
        Assert.Equal(AuthorizationDetailTypeConstants.OpenId, authorizationDetailTypeConsent.AuthorizationDetailType.Name);
    }

    [Fact]
    public async Task CreateOrUpdateClientConsent_ExistingConsent_ExpectUpdateClientConsent()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var consentRepository = serviceProvider.GetRequiredService<IConsentRepository>();

        var subjectIdentifier = new SubjectIdentifier();
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(new ScopeConsent(subjectIdentifier, client, await GetScope(ScopeConstants.Profile)));
        await AddEntity(new ClaimConsent(subjectIdentifier, client, await GetClaim(ClaimNameConstants.Birthdate)));
        await AddEntity(new AuthorizationDetailTypeConsent(subjectIdentifier, client, await GetAuthorizationDetailType(AuthorizationDetailTypeConstants.Profile)));

        // Act
        await consentRepository.CreateOrUpdateClientConsent(
            new ConsentDto
            {
                SubjectIdentifier = subjectIdentifier.Id,
                ClientId = client.Id,
                ConsentedScopes = [ScopeConstants.OpenId],
                ConsentedClaims = [ClaimNameConstants.Name],
                ConsentedAuthorizationDetailTypes = [AuthorizationDetailTypeConstants.OpenId]
            },
            CancellationToken.None);

        // Assert
        var consents = await IdentityContext
            .Set<Consent>()
            .Where(x => x.SubjectIdentifier.Id == subjectIdentifier.Id)
            .Where(x => x.Client.Id == client.Id)
            .ToListAsync();

        Assert.Equal(5, consents.Count);

        Assert.Collection(
            consents.OfType<ScopeConsent>(),
            sc => Assert.Equal(ScopeConstants.Profile, sc.Scope.Name),
            sc => Assert.Equal(ScopeConstants.OpenId, sc.Scope.Name)
        );

        var claimConsents = consents.OfType<ClaimConsent>().ToList();
        Assert.Single(claimConsents);
        Assert.Equal(ClaimNameConstants.Name, claimConsents.Single().Claim.Name);

        Assert.Collection(
            consents.OfType<AuthorizationDetailTypeConsent>(),
            adtc => Assert.Equal(AuthorizationDetailTypeConstants.Profile, adtc.AuthorizationDetailType.Name),
            adtc => Assert.Equal(AuthorizationDetailTypeConstants.OpenId, adtc.AuthorizationDetailType.Name)
        );
    }

    [Fact]
    public async Task CreateGrantConsent_WithClientConsents_ExpectGrantConsentCreated()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var consentRepository = serviceProvider.GetRequiredService<IConsentRepository>();

        var authorizationGrant = await GetAuthorizationGrant(
            ScopeConstants.Profile, "https://idp.authserver.dk", ClaimNameConstants.Name, AuthorizationDetailTypeConstants.OpenId);

        authorizationGrant.AuthorizationGrantConsents.Clear();
        await SaveChangesAsync();

        var authorizationDetail = new DefaultAuthorizationDetailDto
        {
            Type = AuthorizationDetailTypeConstants.OpenId
        };
        var rawAuthorizationDetail = JsonSerializer.Serialize(authorizationDetail);
        authorizationDetail.Raw = rawAuthorizationDetail;

        // Act
        await consentRepository.CreateGrantConsent(
            new AuthorizationGrantConsentDto
            {
                AuthorizationGrantId = authorizationGrant.Id,
                Scope = [ScopeConstants.Profile],
                Resource = ["https://idp.authserver.dk"],
                AuthorizationDetails = [authorizationDetail]
            },
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

        var authorizationDetailTypeDtos = authorizationGrant.AuthorizationGrantConsents
            .OfType<AuthorizationGrantAuthorizationDetailTypeConsent>()
            .Select(x => new DefaultAuthorizationDetailDto
            {
                Type = ((AuthorizationDetailTypeConsent)x.Consent).AuthorizationDetailType.Name,
                Raw = x.RawValue
            })
            .ToList();

        Assert.Single(authorizationDetailTypeDtos);
        Assert.Single(authorizationDetailTypeDtos, x => x is { Type: AuthorizationDetailTypeConstants.OpenId });
    }

    [Fact]
    public async Task MergeGrantConsent_WithGrantConsents_ExpectGrantConsentMerged()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var consentRepository = serviceProvider.GetRequiredService<IConsentRepository>();

        var authorizationGrant = await GetAuthorizationGrant(
            ScopeConstants.UserInfo, "https://idp.authserver.dk", ClaimNameConstants.Name, AuthorizationDetailTypeConstants.OpenId);

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

        var authorizationDetailTypeConsent = new AuthorizationDetailTypeConsent(
            authorizationGrant.Session.SubjectIdentifier,
            authorizationGrant.Client,
            await GetAuthorizationDetailType(AuthorizationDetailTypeConstants.Profile));

        await AddEntity(authorizationDetailTypeConsent);

        var authorizationDetail = new DefaultAuthorizationDetailDto
        {
            Type = AuthorizationDetailTypeConstants.Profile
        };
        var rawAuthorizationDetail = JsonSerializer.Serialize(authorizationDetail);
        authorizationDetail.Raw = rawAuthorizationDetail;

        // Act
        await consentRepository.MergeGrantConsent(
            new AuthorizationGrantConsentDto
            {
                AuthorizationGrantId = authorizationGrant.Id,
                Scope = [ScopeConstants.Profile],
                Resource = ["https://weather.authserver.dk"],
                AuthorizationDetails = [authorizationDetail]
            },
            CancellationToken.None);

        // Assert
        var scopeDtos = authorizationGrant.AuthorizationGrantConsents
            .OfType<AuthorizationGrantScopeConsent>()
            .Select(x => new ScopeDto(((ScopeConsent)x.Consent).Scope.Name, x.Resource))
            .ToList();

        Assert.Single(scopeDtos, x => x is { Name: ScopeConstants.UserInfo, Resource: "https://idp.authserver.dk" });
        Assert.Single(scopeDtos, x => x is { Name: ScopeConstants.Profile, Resource: "https://weather.authserver.dk" });

        var claims = authorizationGrant.AuthorizationGrantConsents
            .OfType<AuthorizationGrantClaimConsent>()
            .Select(x => x.Consent)
            .OfType<ClaimConsent>()
            .Select(x => x.Claim.Name)
            .ToList();

        Assert.Equal(2, claims.Count);
        Assert.Single(claims, ClaimNameConstants.Name);
        Assert.Single(claims, ClaimNameConstants.FamilyName);

        var authorizationDetailTypeDtos = authorizationGrant.AuthorizationGrantConsents
            .OfType<AuthorizationGrantAuthorizationDetailTypeConsent>()
            .Select(x => new DefaultAuthorizationDetailDto
            {
                Type = ((AuthorizationDetailTypeConsent)x.Consent).AuthorizationDetailType.Name,
                Raw = x.RawValue
            })
            .ToList();

        Assert.Equal(2, authorizationDetailTypeDtos.Count);
        Assert.Single(authorizationDetailTypeDtos, x => x is { Type: AuthorizationDetailTypeConstants.OpenId });
        Assert.Single(authorizationDetailTypeDtos, x => x is { Type: AuthorizationDetailTypeConstants.Profile });
    }

    [Fact]
    public async Task ReplaceGrantConsent_WithGrantConsents_ExpectGrantConsentReplaced()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var consentRepository = serviceProvider.GetRequiredService<IConsentRepository>();

        var authorizationGrant = await GetAuthorizationGrant(
            ScopeConstants.UserInfo, "https://idp.authserver.dk", ClaimNameConstants.FamilyName, AuthorizationDetailTypeConstants.OpenId);

        var scopeConsent = new ScopeConsent(
            authorizationGrant.Session.SubjectIdentifier,
            authorizationGrant.Client,
            await GetScope(ScopeConstants.Profile));

        await AddEntity(scopeConsent);

        var authorizationDetailTypeConsent = new AuthorizationDetailTypeConsent(
            authorizationGrant.Session.SubjectIdentifier,
            authorizationGrant.Client,
            await GetAuthorizationDetailType(AuthorizationDetailTypeConstants.Profile));

        await AddEntity(authorizationDetailTypeConsent);

        var authorizationDetail = new DefaultAuthorizationDetailDto
        {
            Type = AuthorizationDetailTypeConstants.Profile
        };
        var rawAuthorizationDetail = JsonSerializer.Serialize(authorizationDetail);
        authorizationDetail.Raw = rawAuthorizationDetail;

        // Act
        await consentRepository.ReplaceGrantConsent(
            new AuthorizationGrantConsentDto
            {
                AuthorizationGrantId = authorizationGrant.Id,
                Scope = [ScopeConstants.Profile],
                Resource = ["https://weather.authserver.dk"],
                AuthorizationDetails = [authorizationDetail]
            },
            CancellationToken.None);

        // Assert
        var scopeDtos = authorizationGrant.AuthorizationGrantConsents
            .OfType<AuthorizationGrantScopeConsent>()
            .Select(x => new ScopeDto(((ScopeConsent)x.Consent).Scope.Name, x.Resource))
            .ToList();

        Assert.Single(scopeDtos);
        Assert.Single(scopeDtos, x => x is { Name: ScopeConstants.Profile, Resource: "https://weather.authserver.dk" });

        var claims = authorizationGrant.AuthorizationGrantConsents
            .OfType<AuthorizationGrantClaimConsent>()
            .Select(x => x.Consent)
            .OfType<ClaimConsent>()
            .Select(x => x.Claim.Name)
            .ToList();

        Assert.Single(claims);
        Assert.Single(claims, ClaimNameConstants.FamilyName);

        var authorizationDetailTypeDtos = authorizationGrant.AuthorizationGrantConsents
            .OfType<AuthorizationGrantAuthorizationDetailTypeConsent>()
            .Select(x => new DefaultAuthorizationDetailDto
            {
                Type = ((AuthorizationDetailTypeConsent)x.Consent).AuthorizationDetailType.Name,
                Raw = x.RawValue
            })
            .ToList();

        Assert.Single(authorizationDetailTypeDtos);
        Assert.Single(authorizationDetailTypeDtos, x => x is { Type: AuthorizationDetailTypeConstants.Profile });
    }

    private async Task<(string SubjectIdentifier, string ClientId)> GetClientConsent(string scope, string claim, string authorizationDetailType)
    {
        var subjectIdentifier = new SubjectIdentifier();
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var scopeConsent = new ScopeConsent(subjectIdentifier, client, await GetScope(scope));
        var claimConsent = new ClaimConsent(subjectIdentifier, client, await GetClaim(claim));
        var authorizationDetailTypeConsent = new AuthorizationDetailTypeConsent(subjectIdentifier, client, await GetAuthorizationDetailType(authorizationDetailType));

        await AddEntity(scopeConsent);
        await AddEntity(claimConsent);
        await AddEntity(authorizationDetailTypeConsent);

        return (subjectIdentifier.Id, client.Id);
    }

    private async Task<AuthorizationGrant> GetAuthorizationGrant(string scope, string resource, string claim, string authorizationDetailType)
    {
        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var authenticationContextReference = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, authenticationContextReference);

        var scopeConsent = new ScopeConsent(subjectIdentifier, client, await GetScope(scope));
        var authorizationGrantScopeConsent = new AuthorizationGrantScopeConsent(scopeConsent, authorizationGrant, resource);
        authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantScopeConsent);

        var claimConsent = new ClaimConsent(subjectIdentifier, client, await GetClaim(claim));
        var authorizationGrantClaimConsent = new AuthorizationGrantClaimConsent(claimConsent, authorizationGrant);
        authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantClaimConsent);

        var authorizationDetailTypeConsent = new AuthorizationDetailTypeConsent(subjectIdentifier, client, await GetAuthorizationDetailType(authorizationDetailType));
        var rawAuthorizationDetails = JsonSerializer.Serialize(new List<DefaultAuthorizationDetailDto>
        {
            new()
            {
                Type = authorizationDetailType
            }
        });
        var authorizationGrantAuthorizationDetailTypeConsent = new AuthorizationGrantAuthorizationDetailTypeConsent(authorizationDetailTypeConsent, authorizationGrant, rawAuthorizationDetails);
        authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantAuthorizationDetailTypeConsent);

        await AddEntity(authorizationGrant);
        return authorizationGrant;
    }
}