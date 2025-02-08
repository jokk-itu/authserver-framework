using AuthServer.Authentication.Abstractions;
using AuthServer.Authentication.Models;
using AuthServer.Authorize.Abstractions;
using AuthServer.Authorize;
using AuthServer.Constants;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.RequestAccessors.Authorize;
using AuthServer.Tests.Core;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Authorize.Interaction;

public class AuthorizeInteractionServiceCookieTest : BaseUnitTest
{
    public AuthorizeInteractionServiceCookieTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Theory]
    [InlineData(PromptConstants.None)]
    [InlineData(null)]
    public async Task GetInteractionResult_ZeroAuthenticatedUsers_ExpectLogin(string? prompt)
    {
        // Arrange
        var authenticateUserAccessorMock = new Mock<IAuthenticatedUserAccessor>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authenticateUserAccessorMock);
            services.AddScopedMock(new Mock<IAuthorizeUserAccessor>());
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        authenticateUserAccessorMock
            .Setup(x => x.CountAuthenticatedUsers())
            .ReturnsAsync(0)
            .Verifiable();

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                Prompt = prompt
            }, CancellationToken.None);

        // Assert
        Assert.Equal(InteractionResult.LoginResult(prompt), interactionResult);
        Assert.False(interactionResult.IsSuccessful);
        authenticateUserAccessorMock.Verify();
    }

    [Theory]
    [InlineData(PromptConstants.None)]
    [InlineData(null)]
    public async Task GetInteractionResult_MultipleAuthenticatedUsers_ExpectSelectAccount(string? prompt)
    {
        // Arrange
        var authenticateUserAccessorMock = new Mock<IAuthenticatedUserAccessor>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authenticateUserAccessorMock);
            services.AddScopedMock(new Mock<IAuthorizeUserAccessor>());
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        authenticateUserAccessorMock
            .Setup(x => x.CountAuthenticatedUsers())
            .ReturnsAsync(2)
            .Verifiable();

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                Prompt = prompt
            }, CancellationToken.None);

        // Assert
        Assert.Equal(InteractionResult.SelectAccountResult(prompt), interactionResult);
        Assert.False(interactionResult.IsSuccessful);
        authenticateUserAccessorMock.Verify();
    }

    [Theory]
    [InlineData(PromptConstants.None)]
    [InlineData(null)]
    public async Task GetInteractionResult_OneAuthenticationUserWithExpiredGrant_ExpectLogin(string? prompt)
    {
        // Arrange
        var authenticateUserAccessorMock = new Mock<IAuthenticatedUserAccessor>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authenticateUserAccessorMock);
            services.AddScopedMock(new Mock<IAuthorizeUserAccessor>());
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, lowAcr);
        authorizationGrant.Revoke();
        await AddEntity(authorizationGrant);

        authenticateUserAccessorMock
            .Setup(x => x.CountAuthenticatedUsers())
            .ReturnsAsync(1)
            .Verifiable();

        authenticateUserAccessorMock
            .Setup(x => x.GetAuthenticatedUser())
            .ReturnsAsync(new AuthenticatedUser(subjectIdentifier.Id, authorizationGrant.Id))
            .Verifiable();

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id,
                Prompt = prompt
            }, CancellationToken.None);

        // Assert
        Assert.Equal(InteractionResult.LoginResult(prompt), interactionResult);
        Assert.False(interactionResult.IsSuccessful);
        authenticateUserAccessorMock.Verify();
    }

    [Theory]
    [InlineData("none")]
    [InlineData(null)]
    public async Task GetInteractionResult_OneAuthenticatedUserMaxAgeExceeded_ExpectLogin(string? prompt)
    {
        // Arrange
        var authenticateUserAccessorMock = new Mock<IAuthenticatedUserAccessor>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authenticateUserAccessorMock);
            services.AddScopedMock(new Mock<IAuthorizeUserAccessor>());
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, lowAcr);
        typeof(AuthorizationGrant)
            .GetProperty(nameof(AuthorizationGrant.AuthTime))!
            .SetValue(authorizationGrant, DateTime.UtcNow.AddSeconds(-180));

        await AddEntity(authorizationGrant);

        authenticateUserAccessorMock
            .Setup(x => x.CountAuthenticatedUsers())
            .ReturnsAsync(1)
            .Verifiable();

        authenticateUserAccessorMock
            .Setup(x => x.GetAuthenticatedUser())
            .ReturnsAsync(new AuthenticatedUser(subjectIdentifier.Id, authorizationGrant.Id))
            .Verifiable();

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id,
                MaxAge = "30",
                Prompt = prompt
            }, CancellationToken.None);

        // Assert
        Assert.Equal(InteractionResult.LoginResult(prompt), interactionResult);
        Assert.False(interactionResult.IsSuccessful);
        authenticateUserAccessorMock.Verify();
    }

    [Theory]
    [InlineData(PromptConstants.None)]
    [InlineData(null)]
    public async Task GetInteractionResult_OneAuthenticatedUserDefaultMaxAgeExceeded_ExpectLogin(string? prompt)
    {
        // Arrange
        var authenticateUserAccessorMock = new Mock<IAuthenticatedUserAccessor>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authenticateUserAccessorMock);
            services.AddScopedMock(new Mock<IAuthorizeUserAccessor>());
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic)
        {
            DefaultMaxAge = 30
        };
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, lowAcr);
        typeof(AuthorizationGrant)
            .GetProperty(nameof(AuthorizationGrant.AuthTime))!
            .SetValue(authorizationGrant, DateTime.UtcNow.AddSeconds(-180));

        await AddEntity(authorizationGrant);

        authenticateUserAccessorMock
            .Setup(x => x.CountAuthenticatedUsers())
            .ReturnsAsync(1)
            .Verifiable();

        authenticateUserAccessorMock
            .Setup(x => x.GetAuthenticatedUser())
            .ReturnsAsync(new AuthenticatedUser(subjectIdentifier.Id, authorizationGrant.Id))
            .Verifiable();

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id,
                Prompt = prompt
            }, CancellationToken.None);

        // Assert
        Assert.Equal(InteractionResult.LoginResult(prompt), interactionResult);
        Assert.False(interactionResult.IsSuccessful);
        authenticateUserAccessorMock.Verify();
    }

    [Fact]
    public async Task GetInteractionResult_OneAuthenticatedUserWithInsufficientAuthenticationMethodReferenceAgainstRequest_ExpectUnmetAuthenticationRequirementResult()
    {
        // Arrange
        var authenticateUserAccessorMock = new Mock<IAuthenticatedUserAccessor>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authenticateUserAccessorMock);
            services.AddScopedMock(new Mock<IAuthorizeUserAccessor>());
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, lowAcr)
        {
            AuthenticationMethodReferences =
                [await GetAuthenticationMethodReference(AuthenticationMethodReferenceConstants.Password)]
        };
        await AddEntity(authorizationGrant);

        authenticateUserAccessorMock
            .Setup(x => x.CountAuthenticatedUsers())
            .ReturnsAsync(1)
            .Verifiable();

        authenticateUserAccessorMock
            .Setup(x => x.GetAuthenticatedUser())
            .ReturnsAsync(new AuthenticatedUser(subjectIdentifier.Id, authorizationGrant.Id))
            .Verifiable();

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id,
                AcrValues = [LevelOfAssuranceSubstantial]
            }, CancellationToken.None);

        // Assert
        Assert.Equal(InteractionResult.UnmetAuthenticationRequirementResult, interactionResult);
        Assert.False(interactionResult.IsSuccessful);
        authenticateUserAccessorMock.Verify();
    }

    [Fact]
    public async Task GetInteractionResult_OneAuthenticatedUserWithInsufficientAuthenticationMethodReferenceAgainstDefault_ExpectUnmetAuthenticationRequirementResult()
    {
        // Arrange
        var authenticateUserAccessorMock = new Mock<IAuthenticatedUserAccessor>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authenticateUserAccessorMock);
            services.AddScopedMock(new Mock<IAuthorizeUserAccessor>());
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var substantialAcr = await GetAuthenticationContextReference(LevelOfAssuranceSubstantial);
        var clientAuthenticationContextReference = new ClientAuthenticationContextReference(client, substantialAcr, 0);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, lowAcr)
        {
            AuthenticationMethodReferences =
                [await GetAuthenticationMethodReference(AuthenticationMethodReferenceConstants.Password)]
        };
        await AddEntity(authorizationGrant);
        await AddEntity(clientAuthenticationContextReference);

        authenticateUserAccessorMock
            .Setup(x => x.CountAuthenticatedUsers())
            .ReturnsAsync(1)
            .Verifiable();

        authenticateUserAccessorMock
            .Setup(x => x.GetAuthenticatedUser())
            .ReturnsAsync(new AuthenticatedUser(subjectIdentifier.Id, authorizationGrant.Id))
            .Verifiable();

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id
            }, CancellationToken.None);

        // Assert
        Assert.Equal(InteractionResult.UnmetAuthenticationRequirementResult, interactionResult);
        Assert.False(interactionResult.IsSuccessful);
        authenticateUserAccessorMock.Verify();
    }

    [Fact]
    public async Task GetInteractionResult_OneAuthenticatedUserSubjectDoesNotOwnGrant_ExpectInvalidGrantId()
    {
        // Arrange
        var authenticateUserAccessorMock = new Mock<IAuthenticatedUserAccessor>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authenticateUserAccessorMock);
            services.AddScopedMock(new Mock<IAuthorizeUserAccessor>());
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, lowAcr)
        {
            AuthenticationMethodReferences =
                [await GetAuthenticationMethodReference(AuthenticationMethodReferenceConstants.Password)]
        };
        await AddEntity(authorizationGrant);

        authenticateUserAccessorMock
            .Setup(x => x.CountAuthenticatedUsers())
            .ReturnsAsync(1)
            .Verifiable();

        authenticateUserAccessorMock
            .Setup(x => x.GetAuthenticatedUser())
            .ReturnsAsync(new AuthenticatedUser("other_subject", authorizationGrant.Id))
            .Verifiable();

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id,
                GrantId = authorizationGrant.Id
            }, CancellationToken.None);

        // Assert
        Assert.Equal(InteractionResult.InvalidGrantId, interactionResult);
        Assert.False(interactionResult.IsSuccessful);
        authenticateUserAccessorMock.Verify();
    }

    [Fact]
    public async Task GetInteractionResult_OneAuthenticatedUserConsentNotRequired_ExpectNone()
    {
        // Arrange
        var authenticateUserAccessorMock = new Mock<IAuthenticatedUserAccessor>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authenticateUserAccessorMock);
            services.AddScopedMock(new Mock<IAuthorizeUserAccessor>());
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic)
        {
            RequireConsent = false
        };
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, lowAcr);
        await AddEntity(authorizationGrant);

        authenticateUserAccessorMock
            .Setup(x => x.CountAuthenticatedUsers())
            .ReturnsAsync(1)
            .Verifiable();

        authenticateUserAccessorMock
            .Setup(x => x.GetAuthenticatedUser())
            .ReturnsAsync(new AuthenticatedUser(subjectIdentifier.Id, authorizationGrant.Id))
            .Verifiable();

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id
            }, CancellationToken.None);

        // Assert
        Assert.Equal(subjectIdentifier.Id, interactionResult.SubjectIdentifier);
        Assert.True(interactionResult.IsSuccessful);
        authenticateUserAccessorMock.Verify();
    }

    [Theory]
    [InlineData(PromptConstants.None)]
    [InlineData(null)]
    public async Task GetInteractionResult_OneAuthenticatedUserConsentRequired_ExpectConsent(string? prompt)
    {
        // Arrange
        var authenticateUserAccessorMock = new Mock<IAuthenticatedUserAccessor>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authenticateUserAccessorMock);
            services.AddScopedMock(new Mock<IAuthorizeUserAccessor>());
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, lowAcr);
        await AddEntity(authorizationGrant);

        authenticateUserAccessorMock
            .Setup(x => x.CountAuthenticatedUsers())
            .ReturnsAsync(1)
            .Verifiable();

        authenticateUserAccessorMock
            .Setup(x => x.GetAuthenticatedUser())
            .ReturnsAsync(new AuthenticatedUser(subjectIdentifier.Id, authorizationGrant.Id))
            .Verifiable();

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id,
                Scope = [ScopeConstants.OpenId],
                Prompt = prompt
            }, CancellationToken.None);

        // Assert
        Assert.Equal(InteractionResult.ConsentResult(prompt), interactionResult);
        Assert.False(interactionResult.IsSuccessful);
        authenticateUserAccessorMock.Verify();
    }

    [Fact]
    public async Task GetInteractionResult_OneAuthenticatedUserConsentRequired_ExpectNone()
    {
        // Arrange
        var authenticateUserAccessorMock = new Mock<IAuthenticatedUserAccessor>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authenticateUserAccessorMock);
            services.AddScopedMock(new Mock<IAuthorizeUserAccessor>());
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, lowAcr);
        await AddEntity(authorizationGrant);

        var consentGrant = new ConsentGrant(subjectIdentifier, client);
        consentGrant.ConsentedScopes.Add(IdentityContext.Set<Scope>().Single(x => x.Name == ScopeConstants.OpenId));
        await AddEntity(consentGrant);

        authenticateUserAccessorMock
            .Setup(x => x.CountAuthenticatedUsers())
            .ReturnsAsync(1)
            .Verifiable();

        authenticateUserAccessorMock
            .Setup(x => x.GetAuthenticatedUser())
            .ReturnsAsync(new AuthenticatedUser(subjectIdentifier.Id, authorizationGrant.Id))
            .Verifiable();

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id,
                Scope = [ScopeConstants.OpenId]
            }, CancellationToken.None);

        // Assert
        Assert.Equal(subjectIdentifier.Id, interactionResult.SubjectIdentifier);
        Assert.True(interactionResult.IsSuccessful);
        authenticateUserAccessorMock.Verify();
    }
}
