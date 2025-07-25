using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Extensions;
using AuthServer.GrantManagement;
using AuthServer.GrantManagement.Query;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.GrantManagement;

public class GrantManagementQueryRequestProcessorTest : BaseUnitTest
{
    public GrantManagementQueryRequestProcessorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task Process_GrantConsents_ExpectGrantResponse()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var processor = serviceProvider
            .GetRequiredService<IRequestProcessor<GrantManagementValidatedRequest, GrantResponse>>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);

        var openIdScope = await GetScope(ScopeConstants.OpenId);
        var scopeConsent = new ScopeConsent(subjectIdentifier, client, openIdScope);
        var authorizationGrantScopeConsent = new AuthorizationGrantScopeConsent(scopeConsent, authorizationGrant, "https://weather.authserver.dk");
        authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantScopeConsent);

        var nameClaim = await GetClaim(ClaimNameConstants.Name);
        var claimConsent = new ClaimConsent(subjectIdentifier, client, nameClaim);
        var authorizationGrantClaimConsent = new AuthorizationGrantClaimConsent(claimConsent, authorizationGrant);
        authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantClaimConsent);

        await AddEntity(authorizationGrant);


        var request = new GrantManagementValidatedRequest
        {
            GrantId = authorizationGrant.Id
        };

        // Act
        var grantResponse = await processor.Process(request, CancellationToken.None);

        // Assert
        Assert.Equal(authorizationGrant.CreatedAuthTime.ToUnixTimeSeconds(), grantResponse.CreatedAt);
        Assert.Equal(authorizationGrant.UpdatedAuthTime.ToUnixTimeSeconds(), grantResponse.UpdatedAt);

        Assert.Single(grantResponse.Claims);
        Assert.Equal(nameClaim.Name, grantResponse.Claims.Single());

        Assert.Single(grantResponse.Scopes);
        var scopeDto = grantResponse.Scopes.Single();
        
        Assert.Single(scopeDto.Scopes);
        Assert.Equal(openIdScope.Name, scopeDto.Scopes.Single());

        Assert.Single(scopeDto.Resources);
        Assert.Equal(authorizationGrantScopeConsent.Resource, scopeDto.Resources.Single());
    }
}