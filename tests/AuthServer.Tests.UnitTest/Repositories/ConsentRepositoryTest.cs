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

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var authenticationContextReference = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, authenticationContextReference);
        var openIdScope = await GetScope(ScopeConstants.OpenId);
        var scopeConsent = new ScopeConsent(subjectIdentifier, client, openIdScope);
        var authorizationGrantScopeConsent = new AuthorizationGrantScopeConsent(scopeConsent, authorizationGrant, "https://weather.authserver.dk");
        authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantScopeConsent);
        await AddEntity(authorizationGrant);

        var otherAuthorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, authenticationContextReference);
        var profileScope = await GetScope(ScopeConstants.Profile);
        var otherScopeConsent = new ScopeConsent(subjectIdentifier, client, profileScope);
        var otherAuthorizationGrantScopeConsent = new AuthorizationGrantScopeConsent(otherScopeConsent, otherAuthorizationGrant, "https://idp.authserver.dk");
        otherAuthorizationGrant.AuthorizationGrantConsents.Add(otherAuthorizationGrantScopeConsent);
        await AddEntity(otherAuthorizationGrant);

        // Act
        var grantConsentedScopes = await consentRepository.GetGrantConsentedScopes(authorizationGrant.Id, CancellationToken.None);

        // Assert
        Assert.Single(grantConsentedScopes);

        var scopeDto = grantConsentedScopes.Single();
        Assert.Equal(openIdScope.Name, scopeDto.Name);
        Assert.Equal(authorizationGrantScopeConsent.Resource, scopeDto.Resource);
    }

    [Fact]
    public async Task GetGrantConsentedClaims_TwoGrantsWithGrantConsentedClaims_ExpectOneGrantConsentedClaim()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var consentRepository = serviceProvider.GetRequiredService<IConsentRepository>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var authenticationContextReference = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, authenticationContextReference);
        var nameClaim = await GetClaim(ClaimNameConstants.Name);
        var claimConsent = new ClaimConsent(subjectIdentifier, client, nameClaim);
        var authorizationGrantClaimConsent = new AuthorizationGrantClaimConsent(claimConsent, authorizationGrant);
        authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantClaimConsent);
        await AddEntity(authorizationGrant);

        var otherAuthorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, authenticationContextReference);
        var addressClaim = await GetClaim(ClaimNameConstants.Address);
        var otherClaimConsent = new ClaimConsent(subjectIdentifier, client, addressClaim);
        var otherAuthorizationGrantClaimConsent = new AuthorizationGrantClaimConsent(otherClaimConsent, otherAuthorizationGrant);
        otherAuthorizationGrant.AuthorizationGrantConsents.Add(otherAuthorizationGrantClaimConsent);
        await AddEntity(otherAuthorizationGrant);

        // Act
        var grantConsentedClaims = await consentRepository.GetGrantConsentedClaims(authorizationGrant.Id, CancellationToken.None);

        // Assert
        Assert.Single(grantConsentedClaims);
        Assert.Equal(nameClaim.Name, grantConsentedClaims.Single());
    }


}