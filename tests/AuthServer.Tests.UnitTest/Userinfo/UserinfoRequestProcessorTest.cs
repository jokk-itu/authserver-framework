using System.Text.Json;
using AuthServer.Authentication.Abstractions;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Helpers;
using AuthServer.Tests.Core;
using AuthServer.Userinfo;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Moq;
using Xunit.Abstractions;
using Claim = System.Security.Claims.Claim;

namespace AuthServer.Tests.UnitTest.Userinfo;
public class UserinfoRequestProcessorTest : BaseUnitTest
{
    public UserinfoRequestProcessorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task Process_NoUserinfoSignatureWithNoConsent_ExpectJsonSerializedClaims()
    {
        // Arrange
        var userClaimService = new Mock<IUserClaimService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(userClaimService);
        });
        var processor = serviceProvider.GetRequiredService<IRequestProcessor<UserinfoValidatedRequest, string>>();

        var authorizationGrant = await GetAuthorizationGrant(false);

        const string address = "PinguStreet";
        userClaimService
            .Setup(x => x.GetClaims(authorizationGrant.Subject, CancellationToken.None))
            .ReturnsAsync([new Claim(ClaimNameConstants.Address, address)])
            .Verifiable();

        // Act
        var jsonClaims = await processor.Process(new UserinfoValidatedRequest
        {
            AuthorizationGrantId = authorizationGrant.Id,
            Scope = [ScopeConstants.OpenId, ScopeConstants.UserInfo, ScopeConstants.Address]
        }, CancellationToken.None);
        var claims = JsonSerializer.Deserialize<IDictionary<string, string>>(jsonClaims)!;

        // Assert
        userClaimService.Verify();

        Assert.Equal(authorizationGrant.Subject, claims[ClaimNameConstants.Sub]);
        Assert.Equal(address, claims[ClaimNameConstants.Address]);
    }

    [Fact]
    public async Task Process_NoUserinfoSignatureWithConsent_ExpectJsonSerializedClaims()
    {
        // Arrange
        var userClaimService = new Mock<IUserClaimService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(userClaimService);
        });
        var processor = serviceProvider.GetRequiredService<IRequestProcessor<UserinfoValidatedRequest, string>>();

        var authorizationGrant = await GetAuthorizationGrant(true);

        const string address = "PinguStreet";
        userClaimService
            .Setup(x => x.GetClaims(authorizationGrant.Subject, CancellationToken.None))
            .ReturnsAsync([new Claim(ClaimNameConstants.Address, address)])
            .Verifiable();

        // Act
        var jsonClaims = await processor.Process(new UserinfoValidatedRequest
        {
            AuthorizationGrantId = authorizationGrant.Id,
            Scope = [ScopeConstants.OpenId, ScopeConstants.UserInfo, ScopeConstants.Address]
        }, CancellationToken.None);
        var claims = JsonSerializer.Deserialize<IDictionary<string, string>>(jsonClaims)!;

        // Assert
        userClaimService.Verify();

        Assert.Equal(authorizationGrant.Subject, claims[ClaimNameConstants.Sub]);
        Assert.Equal(address, claims[ClaimNameConstants.Address]);
    }

    [Fact]
    public async Task Process_UserinfoSignatureWithNoConsent_ExpectJwtClaims()
    {
        // Arrange
        var userClaimService = new Mock<IUserClaimService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(userClaimService);
        });
        var processor = serviceProvider.GetRequiredService<IRequestProcessor<UserinfoValidatedRequest, string>>();

        var authorizationGrant = await GetAuthorizationGrant(false);
        authorizationGrant.Client.UserinfoSignedResponseAlg = SigningAlg.RsaSha256;
        await SaveChangesAsync();

        const string address = "PinguStreet";
        userClaimService
            .Setup(x => x.GetClaims(authorizationGrant.Subject, CancellationToken.None))
            .ReturnsAsync([new Claim(ClaimNameConstants.Address, address)])
            .Verifiable();

        // Act
        var jsonWebToken = await processor.Process(new UserinfoValidatedRequest
        {
            AuthorizationGrantId = authorizationGrant.Id,
            Scope = [ScopeConstants.OpenId, ScopeConstants.UserInfo, ScopeConstants.Address]
        }, CancellationToken.None);

        // Assert
        userClaimService.Verify();

        Assert.True(TokenHelper.IsJws(jsonWebToken));

        var deserializedToken = new JsonWebTokenHandler().ReadJsonWebToken(jsonWebToken);

        Assert.Equal(authorizationGrant.Subject, deserializedToken.Subject);
        Assert.Equal(address, deserializedToken.GetClaim(ClaimNameConstants.Address).Value);
    }

    [Fact]
    public async Task Process_UserinfoSignatureWithConsent_ExpectJwtClaims()
    {
        // Arrange
        var userClaimService = new Mock<IUserClaimService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(userClaimService);
        });
        var processor = serviceProvider.GetRequiredService<IRequestProcessor<UserinfoValidatedRequest, string>>();

        var authorizationGrant = await GetAuthorizationGrant(true);
        authorizationGrant.Client.UserinfoSignedResponseAlg = SigningAlg.RsaSha256;
        await SaveChangesAsync();

        const string address = "PinguStreet";
        userClaimService
            .Setup(x => x.GetClaims(authorizationGrant.Subject, CancellationToken.None))
            .ReturnsAsync([new Claim(ClaimNameConstants.Address, address)])
            .Verifiable();

        // Act
        var jsonWebToken = await processor.Process(new UserinfoValidatedRequest
        {
            AuthorizationGrantId = authorizationGrant.Id,
            Scope = [ScopeConstants.OpenId, ScopeConstants.UserInfo, ScopeConstants.Address]
        }, CancellationToken.None);

        // Assert
        userClaimService.Verify();

        Assert.True(TokenHelper.IsJws(jsonWebToken));

        var deserializedToken = new JsonWebTokenHandler().ReadJsonWebToken(jsonWebToken);

        Assert.Equal(authorizationGrant.Subject, deserializedToken.Subject);
        Assert.Equal(address, deserializedToken.GetClaim(ClaimNameConstants.Address).Value);
    }

    private async Task<AuthorizationGrant> GetAuthorizationGrant(bool requireConsent)
    {
        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);

        var client = new Client("webapp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            RequireConsent = requireConsent,
            ClientUri = "https://webapp.authserver.dk"
        };
        var addressScope = await GetScope(ScopeConstants.Address);
        client.Scopes.Add(addressScope);

        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, lowAcr);

        var scopeConsent = new ScopeConsent(subjectIdentifier, client, addressScope);
        var authorizationGrantScopeConsent = new AuthorizationGrantScopeConsent(scopeConsent, authorizationGrant, "https://weather.authserver.dk");
        authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantScopeConsent);

        var addressClaim = await GetClaim(ClaimNameConstants.Address);
        var claimConsent = new ClaimConsent(subjectIdentifier, client, addressClaim);
        var authorizationGrantClaimConsent = new AuthorizationGrantClaimConsent(claimConsent, authorizationGrant);
        authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantClaimConsent);

        await AddEntity(authorizationGrant);

        return authorizationGrant;
    }
}
