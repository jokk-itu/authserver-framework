using AuthServer.Authorize.Abstractions;
using AuthServer.Authorize;
using AuthServer.Constants;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Tests.Core;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;
using AuthServer.Authentication.Abstractions;

namespace AuthServer.Tests.UnitTest.Authorize.Interaction;

public class AuthorizeInteractionServiceCallbackTest : BaseUnitTest
{
    public AuthorizeInteractionServiceCallbackTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Theory]
    [InlineData(PromptConstants.Login)]
    [InlineData(null)]
    public async Task GetInteractionResult_CallbackExpiredGrant_ExpectLogin(string? prompt)
    {
        // Arrange
        var authorizeUserAccessorMock = new Mock<IUserAccessor<AuthorizeUser>>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(authorizeUserAccessorMock); });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, lowAcr);
        authorizationGrant.Revoke();

        await AddEntity(authorizationGrant);

        var authorizeUser = new AuthorizeUser(subjectIdentifier.Id, false, authorizationGrant.Id);
        authorizeUserAccessorMock
            .Setup(x => x.TryGetUser())
            .Returns(authorizeUser)
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
        Assert.Equal(InteractionResult.LoginResult(prompt), interactionResult);
        Assert.False(interactionResult.IsSuccessful);
        authorizeUserAccessorMock.Verify();
    }

    [Theory]
    [InlineData(PromptConstants.Login)]
    [InlineData(null)]
    public async Task GetInteractionResult_CallbackMaxAgeExceeded_ExpectLogin(string? prompt)
    {
        // Arrange
        var authorizeUserAccessorMock = new Mock<IUserAccessor<AuthorizeUser>>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(authorizeUserAccessorMock); });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, lowAcr);
        typeof(AuthorizationGrant)
            .GetProperty(nameof(AuthorizationGrant.UpdatedAuthTime))!
            .SetValue(authorizationGrant, DateTime.UtcNow.AddSeconds(-180));

        await AddEntity(authorizationGrant);

        var authorizeUser = new AuthorizeUser(subjectIdentifier.Id, false, authorizationGrant.Id);
        authorizeUserAccessorMock
            .Setup(x => x.TryGetUser())
            .Returns(authorizeUser)
            .Verifiable();

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id,
                Scope = [ScopeConstants.OpenId],
                MaxAge = "30",
                Prompt = prompt
            }, CancellationToken.None);

        // Assert
        Assert.Equal(InteractionResult.LoginResult(prompt), interactionResult);
        Assert.False(interactionResult.IsSuccessful);
        authorizeUserAccessorMock.Verify();
    }

    [Theory]
    [InlineData(PromptConstants.Login)]
    [InlineData(null)]
    public async Task GetInteractionResult_CallbackDefaultMaxAgeExceeded_ExpectLogin(string? prompt)
    {
        // Arrange
        var authorizeUserAccessorMock = new Mock<IUserAccessor<AuthorizeUser>>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(authorizeUserAccessorMock); });
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
            .GetProperty(nameof(AuthorizationGrant.UpdatedAuthTime))!
            .SetValue(authorizationGrant, DateTime.UtcNow.AddSeconds(-180));

        await AddEntity(authorizationGrant);

        var authorizeUser = new AuthorizeUser(subjectIdentifier.Id, false, authorizationGrant.Id);
        authorizeUserAccessorMock
            .Setup(x => x.TryGetUser())
            .Returns(authorizeUser)
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
        Assert.Equal(InteractionResult.LoginResult(prompt), interactionResult);
        Assert.False(interactionResult.IsSuccessful);
        authorizeUserAccessorMock.Verify();
    }

    [Fact]
    public async Task GetInteractionResult_CallbackInsufficientAuthenticationMethodReferenceAgainstRequest_ExpectUnmetAuthenticationRequirementResult()
    {
        // Arrange
        var authorizeUserAccessorMock = new Mock<IUserAccessor<AuthorizeUser>>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(authorizeUserAccessorMock); });
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

        var authorizeUser = new AuthorizeUser(subjectIdentifier.Id, true, authorizationGrant.Id);
        authorizeUserAccessorMock
            .Setup(x => x.TryGetUser())
            .Returns(authorizeUser)
            .Verifiable();

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id,
                Scope = [ScopeConstants.OpenId],
                AcrValues = [LevelOfAssuranceSubstantial]
            }, CancellationToken.None);

        // Assert
        Assert.Equal(InteractionResult.UnmetAuthenticationRequirementResult, interactionResult);
        Assert.False(interactionResult.IsSuccessful);
        authorizeUserAccessorMock.Verify();
    }

    [Fact]
    public async Task GetInteractionResult_CallbackInsufficientAuthenticationMethodReferenceAgainstDefault_ExpectUnmetAuthenticationRequirementResult()
    {
        // Arrange
        var authorizeUserAccessorMock = new Mock<IUserAccessor<AuthorizeUser>>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(authorizeUserAccessorMock); });
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

        var authorizeUser = new AuthorizeUser(subjectIdentifier.Id, true, authorizationGrant.Id);
        authorizeUserAccessorMock
            .Setup(x => x.TryGetUser())
            .Returns(authorizeUser)
            .Verifiable();

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id,
                Scope = [ScopeConstants.OpenId],
            }, CancellationToken.None);

        // Assert
        Assert.Equal(InteractionResult.UnmetAuthenticationRequirementResult, interactionResult);
        Assert.False(interactionResult.IsSuccessful);
        authorizeUserAccessorMock.Verify();
    }

    [Fact]
    public async Task GetInteractionResult_CallbackSubjectDoesNotOwnGrant_ExpectInvalidGrantId()
    {
        // Arrange
        var authorizeUserAccessorMock = new Mock<IUserAccessor<AuthorizeUser>>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(authorizeUserAccessorMock); });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, lowAcr);
        await AddEntity(authorizationGrant);

        var authorizeUser = new AuthorizeUser("other_subject", true, authorizationGrant.Id);
        authorizeUserAccessorMock
            .Setup(x => x.TryGetUser())
            .Returns(authorizeUser)
            .Verifiable();

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id,
                Scope = [ScopeConstants.OpenId],
                GrantId = authorizationGrant.Id
            }, CancellationToken.None);

        // Assert
        Assert.Equal(InteractionResult.InvalidGrantId, interactionResult);
        Assert.False(interactionResult.IsSuccessful);
        authorizeUserAccessorMock.Verify();
    }

    [Fact]
    public async Task GetInteractionResult_CallbackConsentNotRequired_ExpectNone()
    {
        // Arrange
        var authorizeUserAccessorMock = new Mock<IUserAccessor<AuthorizeUser>>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(authorizeUserAccessorMock); });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic)
        {
            RequireConsent = false,
        };
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, lowAcr);
        await AddEntity(authorizationGrant);

        var authorizeUser = new AuthorizeUser(subjectIdentifier.Id, true, authorizationGrant.Id);
        authorizeUserAccessorMock
            .Setup(x => x.TryGetUser())
            .Returns(authorizeUser)
            .Verifiable();

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id,
                Scope = [ScopeConstants.OpenId],
                GrantId = authorizationGrant.Id
            }, CancellationToken.None);

        // Assert
        Assert.Equal(subjectIdentifier.Id, interactionResult.SubjectIdentifier);
        Assert.True(interactionResult.IsSuccessful);
        authorizeUserAccessorMock.Verify();
    }

    [Theory]
    [InlineData(PromptConstants.Login)]
    [InlineData(null)]
    public async Task GetInteractionResult_CallbackConsentRequired_ExpectConsent(string? prompt)
    {
        // Arrange
        var authorizeUserAccessorMock = new Mock<IUserAccessor<AuthorizeUser>>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(authorizeUserAccessorMock); });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, lowAcr);
        await AddEntity(authorizationGrant);

        var authorizeUser = new AuthorizeUser(subjectIdentifier.Id, true, authorizationGrant.Id);
        authorizeUserAccessorMock
            .Setup(x => x.TryGetUser())
            .Returns(authorizeUser)
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
        authorizeUserAccessorMock.Verify();
    }

    [Fact]
    public async Task GetInteractionResult_CallbackFromConsent_ExpectNone()
    {
        // Arrange
        var authorizeUserAccessorMock = new Mock<IUserAccessor<AuthorizeUser>>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(authorizeUserAccessorMock); });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, lowAcr);

        var openIdScope = await GetScope(ScopeConstants.OpenId);
        var scopeConsent = new ScopeConsent(subjectIdentifier, client, openIdScope);
        var authorizationGrantScopeConsent = new AuthorizationGrantScopeConsent(scopeConsent, authorizationGrant, "https://weather.authserver.dk");
        authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantScopeConsent);

        await AddEntity(authorizationGrant);

        var authorizeUser = new AuthorizeUser(subjectIdentifier.Id, true, authorizationGrant.Id);
        authorizeUserAccessorMock
            .Setup(x => x.TryGetUser())
            .Returns(authorizeUser)
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
        authorizeUserAccessorMock.Verify();
    }
}
