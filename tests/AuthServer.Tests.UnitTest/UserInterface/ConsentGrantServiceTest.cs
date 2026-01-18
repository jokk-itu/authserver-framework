using AuthServer.Authentication.Abstractions;
using AuthServer.Cache.Abstractions;
using AuthServer.Constants;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Repositories.Abstractions;
using AuthServer.Tests.Core;
using AuthServer.UserInterface.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.UserInterface;

public class ConsentGrantServiceTest : BaseUnitTest
{
    public ConsentGrantServiceTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task HandleConsent_ValidSubjectIdentifierAndClientId_ExpectConsent()
    {
        // Arrange
        var consentRepositoryMock = new Mock<IConsentRepository>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(consentRepositoryMock);
        });
        var consentGrantService = serviceProvider.GetRequiredService<IConsentGrantService>();

        const string subjectIdentifier = "subject";
        const string clientId = "client_id";
        IReadOnlyCollection<string> scopes = ["scope"];
        IReadOnlyCollection<string> claims = ["claims"];

        consentRepositoryMock
            .Setup(x => x.CreateOrUpdateClientConsent(
                subjectIdentifier,
                clientId,
                scopes,
                claims,
                CancellationToken.None))
            .Returns(Task.CompletedTask)
            .Verifiable();

        // Act
        await consentGrantService.HandleConsent(subjectIdentifier, clientId, scopes, claims, CancellationToken.None);

        // Assert
        consentRepositoryMock.Verify();
    }

    [Fact]
    public async Task GetConsentGrantDto_ValidSubjectIdentifierAndClientId_ExpectConsentGrantDto()
    {
        // Arrange
        var userClaimServiceMock = new Mock<IUserClaimService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(userClaimServiceMock);
        });
        var consentGrantService = serviceProvider.GetRequiredService<IConsentGrantService>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            LogoUri = "http://127.0.0.1/log.png",
            ClientUri = "http://127.0.0.1"
        };

        var subjectIdentifier = new SubjectIdentifier();
        var consents = new List<Consent>
        {
            new ClaimConsent(subjectIdentifier, client, await GetClaim(ClaimNameConstants.Name)),
            new ScopeConsent(subjectIdentifier, client, await GetScope(ScopeConstants.OpenId))
        };
        await AddEntity(consents[0]);
        await AddEntity(consents[1]);

        const string username = "username";
        userClaimServiceMock
            .Setup(x => x.GetUsername(subjectIdentifier.Id, CancellationToken.None))
            .ReturnsAsync(username)
            .Verifiable();

        // Act
        var consentGrantDto = await consentGrantService.GetConsentGrantDto(subjectIdentifier.Id, client.Id, CancellationToken.None);

        // Assert
        Assert.Equal(client.Name, consentGrantDto.ClientName);
        Assert.Equal(client.LogoUri, consentGrantDto.ClientLogoUri);
        Assert.Equal(client.ClientUri, consentGrantDto.ClientUri);
        Assert.Equal(username, consentGrantDto.Username);
        userClaimServiceMock.Verify();
        Assert.Single(consentGrantDto.ConsentedScope);
        Assert.Contains(ScopeConstants.OpenId, consentGrantDto.ConsentedScope);
        Assert.Single(consentGrantDto.ConsentedClaims);
        Assert.Contains(ClaimNameConstants.Name, consentGrantDto.ConsentedClaims);
    }
}