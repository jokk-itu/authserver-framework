using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.GrantManagement;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.GrantManagement;

public class GrantManagementRevokeRequestProcessorTest : BaseUnitTest
{
    public GrantManagementRevokeRequestProcessorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task Process_ActiveGrant_ExpectRevokedGrant()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var processor = serviceProvider.GetRequiredService<IRequestProcessor<GrantManagementValidatedRequest, Unit>>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);
        await AddEntity(authorizationGrant);

        var request = new GrantManagementValidatedRequest
        {
            GrantId = authorizationGrant.Id
        };

        // Act
        await processor.Process(request, CancellationToken.None);

        // Assert
        Assert.NotNull(authorizationGrant.RevokedAt);
    }
}