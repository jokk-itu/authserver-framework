using AuthServer.Authentication.Abstractions;
using AuthServer.EndSession;
using AuthServer.Tests.Core;
using AuthServer.UserInterface.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.UserInterface;

public class EndSessionServiceTest : BaseUnitTest
{
    public EndSessionServiceTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task SetUser_GivenSubjectIdentifier_ExpectUserSet()
    {
        // Arrange
        var endSessionUserAccessorMock = new Mock<IUserAccessor<EndSessionUser>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(endSessionUserAccessorMock);
        });
        var endSessionService = serviceProvider.GetRequiredService<IEndSessionService>();

        // Act
        endSessionService.SetUser(UserConstants.SubjectIdentifier, true);

        // Assert
        endSessionUserAccessorMock.Verify(x =>
            x.SetUser(new EndSessionUser(UserConstants.SubjectIdentifier, true)));
    }
}