using AuthServer.Authentication.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Authorize;
using AuthServer.Constants;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Tests.Core;
using AuthServer.UserInterface.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.UserInterface;

public class AuthorizationCodeGrantServiceTest : BaseUnitTest
{
    public AuthorizationCodeGrantServiceTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("create")]
    public async Task HandleAuthorizationCodeGrant_CreateRequest_ExpectNewGrant(string? grantManagementAction)
    {
        // Arrange
        var authorizeUserAccessorMock = new Mock<IUserAccessor<AuthorizeUser>>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(authorizeUserAccessorMock); });
        var authorizationCodeGrantService = serviceProvider.GetRequiredService<IAuthorizationCodeGrantService>();

        var subjectIdentifier = new SubjectIdentifier();
        await AddEntity(subjectIdentifier);

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            SubjectType = SubjectType.Public
        };
        await AddEntity(client);

        var authorizeRequestDto = new AuthorizeRequestDto
        {
            GrantManagementAction = grantManagementAction,
            ClientId = client.Id
        };

        // Act
        var grantId = await authorizationCodeGrantService.HandleAuthorizationCodeGrant(
            subjectIdentifier.Id,
            authorizeRequestDto,
            [AuthenticationMethodReferenceConstants.Password],
            CancellationToken.None);

        // Assert
        Assert.NotEmpty(grantId);
        authorizeUserAccessorMock.Verify(
            a => a.SetUser(new AuthorizeUser(subjectIdentifier.Id, true, grantId)),
            Times.Once());
    }

    [Theory]
    [InlineData("merge")]
    [InlineData("replace")]
    public async Task HandleAuthorizationCodeGrant_UpdateRequest_ExpectUpdatedGrant(string? grantManagementAction)
    {
        // Arrange
        var authorizeUserAccessorMock = new Mock<IUserAccessor<AuthorizeUser>>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(authorizeUserAccessorMock); });
        var authorizationCodeGrantService = serviceProvider.GetRequiredService<IAuthorizationCodeGrantService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            SubjectType = SubjectType.Public
        };
        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var grant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);
        await AddEntity(grant);

        var authorizeRequestDto = new AuthorizeRequestDto
        {
            GrantManagementAction = grantManagementAction,
            ClientId = client.Id,
            GrantId = grant.Id
        };

        // Act
        var grantId = await authorizationCodeGrantService.HandleAuthorizationCodeGrant(
            subjectIdentifier.Id,
            authorizeRequestDto,
            [AuthenticationMethodReferenceConstants.Password],
            CancellationToken.None);

        // Assert
        Assert.Equal(grant.Id, grantId);
        authorizeUserAccessorMock.Verify(
            a => a.SetUser(new AuthorizeUser(subjectIdentifier.Id, false, grantId)),
            Times.Once());
    }
}