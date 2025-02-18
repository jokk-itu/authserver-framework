using AuthServer.Constants;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Repositories.Abstractions;
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
    public async Task GetGrantConsents_TwoGrantsWithGrantConsents_ExpectOneConsent()
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

        var claimConsent = new ClaimConsent(subjectIdentifier, client, await GetClaim(ClaimNameConstants.Name));
        var authorizationGrantClaimConsent = new AuthorizationGrantClaimConsent(claimConsent, authorizationGrant);
        authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantClaimConsent);

        await AddEntity(authorizationGrant);
        return authorizationGrant;
    }
}