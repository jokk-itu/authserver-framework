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

public class AuthorizeInteractionServiceIdTokenTest : BaseUnitTest
{
    public AuthorizeInteractionServiceIdTokenTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Theory]
    [InlineData("none")]
    [InlineData(null)]
    public async Task GetInteractionResult_IdTokenHintExpiredGrant_ExpectLogin(string? prompt)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(services =>
        {
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
        Assert.Equal(InteractionResult.LoginResult(prompt), interactionResult);
        Assert.False(interactionResult.IsSuccessful);
    }

    [Theory]
    [InlineData("none")]
    [InlineData(null)]
    public async Task GetInteractionResult_IdTokenMaxAgeExceeded_ExpectLogin(string? prompt)
    {
        // Arrange
        var authorizeUserAccessorMock = new Mock<IAuthorizeUserAccessor>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizeUserAccessorMock);
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
        Assert.Equal(InteractionResult.LoginResult(prompt), interactionResult);
        Assert.False(interactionResult.IsSuccessful);
    }

    [Theory]
    [InlineData("none")]
    [InlineData(null)]
    public async Task GetInteractionResult_IdTokenDefaultMaxAgeExceeded_ExpectLogin(string? prompt)
    {
        // Arrange
        var authorizeUserAccessorMock = new Mock<IAuthorizeUserAccessor>();
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
            .GetProperty(nameof(AuthorizationGrant.AuthTime))!
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
        Assert.Equal(InteractionResult.LoginResult(prompt), interactionResult);
        Assert.False(interactionResult.IsSuccessful);
    }

    [Fact]
    public async Task GetInteractionResult_IdTokenHintWithInsufficientAuthenticationMethodReferenceAgainstRequest_ExpectUnmetAuthenticationRequirementResult()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(services =>
        {
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
        Assert.Equal(InteractionResult.UnmetAuthenticationRequirementResult, interactionResult);
        Assert.False(interactionResult.IsSuccessful);
    }

    [Fact]
    public async Task GetInteractionResult_IdTokenHintWithInsufficientAuthenticationMethodReferenceAgainstDefault_ExpectUnmetAuthenticationRequirementResult()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(services =>
        {
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
        Assert.Equal(InteractionResult.UnmetAuthenticationRequirementResult, interactionResult);
        Assert.False(interactionResult.IsSuccessful);
    }

    [Fact]
    public async Task GetInteractionResult_IdTokenHintWithSubjectDoesNotOwnGrant_ExpectInvalidGrantId()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(new Mock<IAuthorizeUserAccessor>());
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, lowAcr);
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
        Assert.Equal(InteractionResult.InvalidGrantId, interactionResult);
        Assert.False(interactionResult.IsSuccessful);
    }

    [Fact]
    public async Task GetInteractionResult_IdTokenHintConsentNotRequired_ExpectNone()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(services =>
        {
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
    [InlineData("none")]
    [InlineData(null)]
    public async Task GetInteractionResult_IdTokenHintConsentRequired_ExpectConsent(string? prompt)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(new Mock<IAuthorizeUserAccessor>());
        });
        var authorizeInteractionService = serviceProvider.GetRequiredService<IAuthorizeInteractionService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("WebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, lowAcr);
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
        Assert.Equal(InteractionResult.ConsentResult(prompt), interactionResult);
        Assert.False(interactionResult.IsSuccessful);
    }

    [Fact]
    public async Task GetInteractionResult_IdTokenHintConsentRequired_ExpectNone()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(services =>
        {
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
