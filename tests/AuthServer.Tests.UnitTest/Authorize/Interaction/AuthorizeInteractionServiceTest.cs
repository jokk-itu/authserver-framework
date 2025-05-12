using AuthServer.Authentication.Abstractions;
using AuthServer.Authorize;
using AuthServer.Authorize.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Tests.Core;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Authorize.Interaction;

public class AuthorizeInteractionServiceTest : BaseUnitTest
{
    public AuthorizeInteractionServiceTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Theory]
    [InlineData(PromptConstants.Consent, ErrorCode.ConsentRequired)]
    [InlineData(PromptConstants.Login, ErrorCode.LoginRequired)]
    [InlineData(PromptConstants.SelectAccount, ErrorCode.AccountSelectionRequired)]
    public async Task GetInteractionResult_ClientProvidedPrompt_ExpectProvidedPrompt(string prompt, string errorCode)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(new Mock<IUserAccessor<AuthorizeUser>>());
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                Prompt = prompt
            }, CancellationToken.None);

        // Assert
        Assert.False(interactionResult.IsSuccessful);
        Assert.Equal(errorCode, interactionResult.Error!.Error);
    }
}