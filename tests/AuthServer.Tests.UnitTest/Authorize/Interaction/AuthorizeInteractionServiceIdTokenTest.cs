using AuthServer.Authentication.Abstractions;
using AuthServer.Authorize;
using AuthServer.Authorize.Abstractions;
using AuthServer.Constants;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Metrics;
using AuthServer.Tests.Core;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Authorize.Interaction;

public class AuthorizeInteractionServiceIdTokenTest : BaseUnitTest
{
    public AuthorizeInteractionServiceIdTokenTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Theory]
    [InlineData(PromptConstants.None)]
    [InlineData(null)]
    public async Task GetInteractionResult_IdTokenHintExpiredGrant_ExpectLogin(string? prompt)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(new Mock<IUserAccessor<AuthorizeUser>>());
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, lowAcr);
        authorizationGrant.Revoke();
        await AddEntity(authorizationGrant);

        var idToken = JwtBuilder.GetIdToken(
            client.Id, authorizationGrant.Id, subjectIdentifier.Id, session.Id,
            [AuthenticationMethodReferenceConstants.Password], LevelOfAssuranceLow);

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                IdTokenHint = idToken,
                Prompt = prompt
            }, CancellationToken.None);

        // Assert
        var expectedInteractionResult = InteractionResult.LoginResult(prompt) with { AuthenticationKind = AuthenticationKind.IdToken };
        Assert.Equal(expectedInteractionResult, interactionResult);
        Assert.False(interactionResult.IsSuccessful);
    }

    [Theory]
    [InlineData(PromptConstants.None)]
    [InlineData(null)]
    public async Task GetInteractionResult_IdTokenMaxAgeExceeded_ExpectLogin(string? prompt)
    {
        // Arrange
        var authorizeUserAccessorMock = new Mock<IUserAccessor<AuthorizeUser>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizeUserAccessorMock);
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, lowAcr);
        typeof(AuthorizationGrant)
            .GetProperty(nameof(AuthorizationGrant.UpdatedAuthTime))!
            .SetValue(authorizationGrant, DateTime.UtcNow.AddSeconds(-180));

        await AddEntity(authorizationGrant);

        var idToken = JwtBuilder.GetIdToken(
            client.Id, authorizationGrant.Id, subjectIdentifier.Id, session.Id,
            [AuthenticationMethodReferenceConstants.Password], LevelOfAssuranceLow);

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id,
                IdTokenHint = idToken,
                MaxAge = "30",
                Prompt = prompt
            }, CancellationToken.None);

        // Assert
        var expectedInteractionResult = InteractionResult.LoginResult(prompt) with { AuthenticationKind = AuthenticationKind.IdToken };
        Assert.Equal(expectedInteractionResult, interactionResult);
        Assert.False(interactionResult.IsSuccessful);
    }

    [Theory]
    [InlineData(PromptConstants.None)]
    [InlineData(null)]
    public async Task GetInteractionResult_IdTokenDefaultMaxAgeExceeded_ExpectLogin(string? prompt)
    {
        // Arrange
        var authorizeUserAccessorMock = new Mock<IUserAccessor<AuthorizeUser>>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(authorizeUserAccessorMock); });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            DefaultMaxAge = 30
        };
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, lowAcr);
        typeof(AuthorizationGrant)
            .GetProperty(nameof(AuthorizationGrant.UpdatedAuthTime))!
            .SetValue(authorizationGrant, DateTime.UtcNow.AddSeconds(-180));

        await AddEntity(authorizationGrant);

        var idToken = JwtBuilder.GetIdToken(
            client.Id, authorizationGrant.Id, subjectIdentifier.Id, session.Id,
            [AuthenticationMethodReferenceConstants.Password], LevelOfAssuranceLow);

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id,
                IdTokenHint = idToken,
                Prompt = prompt
            }, CancellationToken.None);

        // Assert
        var expectedInteractionResult = InteractionResult.LoginResult(prompt) with { AuthenticationKind = AuthenticationKind.IdToken };
        Assert.Equal(expectedInteractionResult, interactionResult);
        Assert.False(interactionResult.IsSuccessful);
    }

    [Fact]
    public async Task GetInteractionResult_IdTokenHintWithInsufficientAuthenticationMethodReferenceAgainstRequest_ExpectUnmetAuthenticationRequirementResult()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(new Mock<IUserAccessor<AuthorizeUser>>());
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, lowAcr)
        {
            AuthenticationMethodReferences =
                [await GetAuthenticationMethodReference(AuthenticationMethodReferenceConstants.Password)]
        };
        await AddEntity(authorizationGrant);

        var idToken = JwtBuilder.GetIdToken(
            client.Id, authorizationGrant.Id, subjectIdentifier.Id, session.Id,
            [AuthenticationMethodReferenceConstants.Password], LevelOfAssuranceLow);

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id,
                IdTokenHint = idToken,
                AcrValues = [LevelOfAssuranceSubstantial]
            }, CancellationToken.None);

        // Assert
        var expectedInteractionResult = InteractionResult.UnmetAuthenticationRequirementResult with { AuthenticationKind = AuthenticationKind.IdToken };
        Assert.Equal(expectedInteractionResult, interactionResult);
        Assert.False(interactionResult.IsSuccessful);
    }

    [Fact]
    public async Task GetInteractionResult_IdTokenHintWithInsufficientAuthenticationMethodReferenceAgainstDefault_ExpectUnmetAuthenticationRequirementResult()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(new Mock<IUserAccessor<AuthorizeUser>>());
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var substantialAcr = await GetAuthenticationContextReference(LevelOfAssuranceSubstantial);
        var clientAuthenticationContextReference = new ClientAuthenticationContextReference(client, substantialAcr, 0);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, lowAcr)
        {
            AuthenticationMethodReferences =
                [await GetAuthenticationMethodReference(AuthenticationMethodReferenceConstants.Password)]
        };
        await AddEntity(authorizationGrant);
        await AddEntity(clientAuthenticationContextReference);

        var idToken = JwtBuilder.GetIdToken(
            client.Id, authorizationGrant.Id, subjectIdentifier.Id, session.Id,
            [AuthenticationMethodReferenceConstants.Password], LevelOfAssuranceLow);

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id,
                IdTokenHint = idToken,
            }, CancellationToken.None);

        // Assert
        var expectedInteractionResult = InteractionResult.UnmetAuthenticationRequirementResult with { AuthenticationKind = AuthenticationKind.IdToken };
        Assert.Equal(expectedInteractionResult, interactionResult);
        Assert.False(interactionResult.IsSuccessful);
    }

    [Fact]
    public async Task GetInteractionResult_IdTokenHintWithSubjectDoesNotOwnGrant_ExpectInvalidGrantId()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(new Mock<IUserAccessor<AuthorizeUser>>());
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, lowAcr);
        await AddEntity(authorizationGrant);

        var idToken = JwtBuilder.GetIdToken(
            client.Id, authorizationGrant.Id, "other_subject", session.Id,
            [AuthenticationMethodReferenceConstants.Password], LevelOfAssuranceLow);

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id,
                IdTokenHint = idToken,
                GrantId = authorizationGrant.Id
            }, CancellationToken.None);

        // Assert
        var expectedInteractionResult = InteractionResult.InvalidGrantId with { AuthenticationKind = AuthenticationKind.IdToken };
        Assert.Equal(expectedInteractionResult, interactionResult);
        Assert.False(interactionResult.IsSuccessful);
    }

    [Fact]
    public async Task GetInteractionResult_IdTokenHintConsentNotRequired_ExpectNone()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(new Mock<IUserAccessor<AuthorizeUser>>());
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            RequireConsent = false
        };
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, lowAcr);
        await AddEntity(authorizationGrant);

        var idToken = JwtBuilder.GetIdToken(
            client.Id, authorizationGrant.Id, subjectIdentifier.Id, session.Id,
            [AuthenticationMethodReferenceConstants.Password], LevelOfAssuranceLow);

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id,
                IdTokenHint = idToken,
                GrantId = authorizationGrant.Id
            }, CancellationToken.None);

        // Assert
        Assert.Equal(subjectIdentifier.Id, interactionResult.SubjectIdentifier);
        Assert.True(interactionResult.IsSuccessful);
    }

    [Theory]
    [InlineData(PromptConstants.None)]
    [InlineData(null)]
    public async Task GetInteractionResult_IdTokenHintConsentRequired_ExpectConsent(string? prompt)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(new Mock<IUserAccessor<AuthorizeUser>>());
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, lowAcr);
        await AddEntity(authorizationGrant);

        var idToken = JwtBuilder.GetIdToken(
            client.Id, authorizationGrant.Id, subjectIdentifier.Id, session.Id,
            [AuthenticationMethodReferenceConstants.Password], LevelOfAssuranceLow);

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id,
                IdTokenHint = idToken,
                Scope = [ScopeConstants.OpenId],
                Prompt = prompt
            }, CancellationToken.None);

        // Assert
        var expectedInteractionResult = InteractionResult.ConsentResult(prompt) with { AuthenticationKind = AuthenticationKind.IdToken };
        Assert.Equal(expectedInteractionResult, interactionResult);
        Assert.False(interactionResult.IsSuccessful);
    }

    [Fact]
    public async Task GetInteractionResult_IdTokenHintConsentRequired_ExpectNone()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(new Mock<IUserAccessor<AuthorizeUser>>());
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, lowAcr);

        var openIdScope = await GetScope(ScopeConstants.OpenId);
        var scopeConsent = new ScopeConsent(subjectIdentifier, client, openIdScope);
        var authorizationGrantScopeConsent = new AuthorizationGrantScopeConsent(scopeConsent, authorizationGrant, "https://weather.authserver.dk");
        authorizationGrant.AuthorizationGrantConsents.Add(authorizationGrantScopeConsent);

        await AddEntity(authorizationGrant);

        var idToken = JwtBuilder.GetIdToken(
            client.Id, authorizationGrant.Id, subjectIdentifier.Id, session.Id,
            [AuthenticationMethodReferenceConstants.Password], LevelOfAssuranceLow);

        // Act
        var interactionResult = await authorizeInteractionService.GetInteractionResult(
            new AuthorizeRequest
            {
                ClientId = client.Id,
                IdTokenHint = idToken,
                Scope = [ScopeConstants.OpenId]
            }, CancellationToken.None);

        // Assert
        Assert.Equal(subjectIdentifier.Id, interactionResult.SubjectIdentifier);
        Assert.True(interactionResult.IsSuccessful);
    }
}
