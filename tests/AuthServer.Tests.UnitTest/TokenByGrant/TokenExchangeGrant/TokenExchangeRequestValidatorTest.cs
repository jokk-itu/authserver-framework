using AuthServer.Authentication.Models;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Endpoints.Responses;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Helpers;
using AuthServer.Tests.Core;
using AuthServer.TokenByGrant;
using AuthServer.TokenByGrant.TokenExchangeGrant;
using AuthServer.TokenByGrant.TokenExchangeGrant.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.TokenByGrant.TokenExchangeGrant;
public class TokenExchangeRequestValidatorTest : BaseUnitTest
{
    public TokenExchangeRequestValidatorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("invalid_grant_type")]
    [InlineData("authorization_code")]
    public async Task Validate_InvalidGrantType_ExpectUnsupportedGrantType(string? grantType)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var request = new TokenRequest
        {
            GrantType = grantType
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.UnsupportedGrantType, processResult);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("invalid_requested_token_type")]
    public async Task Validate_InvalidRequestedTokenType_ExpectInvalidRequestedTokenType(string? requestedTokenType)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = requestedTokenType
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidRequestedTokenType, processResult);
    }

    [Theory]
    [InlineData(null, "actor_token_type")]
    [InlineData("", "actor_token_type")]
    [InlineData("actor_token", null)]
    [InlineData("actor_token", "")]
    public async Task Validate_InvalidActorTokenAndActorTokenType_ExpectInvalidActorTokenAndActorTokenType(string? actorToken, string? actorTokenType)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            ActorToken = actorToken,
            ActorTokenType = actorTokenType
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidActorTokenAndActorTokenType, processResult);
    }

    [Fact]
    public async Task Validate_InvalidActorTokenType_ExpectInvalidActorTokenType()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            ActorToken = "actor_token",
            ActorTokenType = "invalid_actor_token_type"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidActorTokenType, processResult);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task Validate_SubjectTokenNotInRequest_ExpectInvalidSubjectToken(string? subjectToken)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = subjectToken
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidSubjectToken, processResult);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task Validate_SubjectTokenTypeNotInRequest_ExpectInvalidSubjectToken(string? subjectTokenType)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = "subject_token",
            SubjectTokenType = subjectTokenType
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidSubjectTokenType, processResult);
    }

    [Fact]
    public async Task Validate_NoClientAuthentication_ExpectMultipleOrNoneClientMethod()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = "subject_token",
            SubjectTokenType = TokenTypeIdentifier.AccessToken
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.MultipleOrNoneClientMethod, processResult);
    }

    [Fact]
    public async Task Validate_InvalidClientAuthentication_ExpectInvalidClient()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = "subject_token",
            SubjectTokenType = TokenTypeIdentifier.AccessToken,
            ClientAuthentications =
            [
                new ClientIdAuthentication("clientId")
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidClient, processResult);
    }

    [Fact]
    public async Task Validate_ClientIsUnauthorizedForTokenExchangeGrantType_ExpectUnauthorizedForGrantType()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var client = await GetActorClient(plainSecret);
        client.GrantTypes.Clear();
        await SaveChangesAsync();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = "subject_token",
            SubjectTokenType = TokenTypeIdentifier.AccessToken,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.UnauthorizedForGrantType, processResult);
    }

    [Fact]
    public async Task Validate_InvalidSubjectToken_ExpectInvalidSubjectToken()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var client = await GetActorClient(plainSecret);

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = "subject_token",
            SubjectTokenType = TokenTypeIdentifier.AccessToken,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidSubjectToken, processResult);
    }

    [Fact]
    public async Task Validate_DelegatedSubjectTokenAndWithoutActorToken_ExpectInvalidActorToken()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var client = await GetActorClient(plainSecret);

        var subjectToken = await GetClientSubjectToken("subjectActor");

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = subjectToken.Reference,
            SubjectTokenType = TokenTypeIdentifier.AccessToken,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidActorToken, processResult);
    }

    [Fact]
    public async Task Validate_RequestsIdTokenWithClientAccessToken_ExpectInvalidSubjectTokenForRequestedTokenType()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var client = await GetActorClient(plainSecret);

        var subjectToken = await GetClientSubjectToken();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.IdToken,
            SubjectToken = subjectToken.Reference,
            SubjectTokenType = TokenTypeIdentifier.AccessToken,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidSubjectTokenForRequestedTokenType, processResult);
    }

    [Fact]
    public async Task Validate_InvalidActorToken_ExpectInvalidActorToken()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var client = await GetActorClient(plainSecret);

        var subjectToken = await GetClientSubjectToken();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = subjectToken.Reference,
            SubjectTokenType = TokenTypeIdentifier.AccessToken,
            ActorToken = "invalid_actor_token",
            ActorTokenType = TokenTypeIdentifier.AccessToken,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidActorToken, processResult);
    }

    [Fact]
    public async Task Validate_MayActRestrictedSubjectTokenWithUnauthorizedActorToken_ExpectActorIsUnauthorizedForSubjectToken()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var client = await GetActorClient(plainSecret);
        var actorToken = await GetActorToken(client);

        var subjectToken = await GetClientSubjectToken(subjectMayAct: "subject");

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = subjectToken.Reference,
            SubjectTokenType = TokenTypeIdentifier.AccessToken,
            ActorToken = actorToken.Reference,
            ActorTokenType = TokenTypeIdentifier.AccessToken,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.ActorIsUnauthorizedForSubjectToken, processResult);
    }

    [Fact]
    public async Task Validate_RequestDPoPForInvalidTokenType_ExpectInvalidDPoPForRequestedTokenType()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var client = await GetActorClient(plainSecret);

        var subjectToken = await GetGrantSubjectToken();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.IdToken,
            SubjectToken = subjectToken.Reference,
            SubjectTokenType = TokenTypeIdentifier.AccessToken,
            DPoP = "dpop",
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidDPoPForRequestedTokenType, processResult);
    }

    [Fact]
    public async Task Validate_EmptyDPoPForClientRequiringDPoP_ExpectDPoPRequired()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var client = await GetActorClient(plainSecret);
        client.RequireDPoPBoundAccessTokens = true;
        await SaveChangesAsync();

        var subjectToken = await GetGrantSubjectToken();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = subjectToken.Reference,
            SubjectTokenType = TokenTypeIdentifier.AccessToken,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.DPoPRequired, processResult);
    }

    [Fact]
    public async Task Validate_InvalidDPoP_ExpectInvalidDPoP()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var client = await GetActorClient(plainSecret);

        const string invalidDPoP = "invalid_dpop";
        dPoPService
            .Setup(x => x.ValidateDPoP(invalidDPoP, client.Id, CancellationToken.None))
            .ReturnsAsync(new DPoPValidationResult());

        var subjectToken = await GetGrantSubjectToken();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = subjectToken.Reference,
            SubjectTokenType = TokenTypeIdentifier.AccessToken,
            DPoP = invalidDPoP,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidDPoP, processResult);
    }

    [Fact]
    public async Task Validate_InvalidDPoPNonce_ExpectRenewDPoPNonce()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var client = await GetActorClient(plainSecret);

        const string invalidDPoP = "invalid_dpop";
        dPoPService
            .Setup(x => x.ValidateDPoP(invalidDPoP, client.Id, CancellationToken.None))
            .ReturnsAsync(new DPoPValidationResult
            {
                RenewDPoPNonce = true
            });

        var subjectToken = await GetGrantSubjectToken();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = subjectToken.Reference,
            SubjectTokenType = TokenTypeIdentifier.AccessToken,
            DPoP = invalidDPoP,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.RenewDPoPNonce(client.Id), processResult);
    }

    [Fact]
    public async Task Validate_ClientRequiresConsentWithoutConsent_ExpectConsentRequired()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var client = await GetActorClient(plainSecret);

        var subjectToken = await GetGrantSubjectToken();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = subjectToken.Reference,
            SubjectTokenType = TokenTypeIdentifier.AccessToken,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.ConsentRequired, processResult);
    }

    [Fact]
    public async Task Validate_ClientRequiresConsentWithExceededScope_ExpectScopeExceedsConsentedScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var client = await GetActorClient(plainSecret);

        var subjectToken = await GetConsentedGrantSubjectToken();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = subjectToken.Reference,
            SubjectTokenType = TokenTypeIdentifier.AccessToken,
            Scope = [ScopeConstants.UserInfo],
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.ScopeExceedsConsentedScope, processResult);
    }

    [Fact]
    public async Task Validate_ClientDoesNotRequireConsent_ExpectUnauthorizedForScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var client = await GetActorClient(plainSecret);

        var subjectToken = await GetClientSubjectToken();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = subjectToken.Reference,
            SubjectTokenType = TokenTypeIdentifier.AccessToken,
            Scope = [ScopeConstants.UserInfo],
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.UnauthorizedForScope, processResult);
    }

    [Fact]
    public async Task Validate_ResourceIsNotAuthorizedForScope_ExpectInvalidResource()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var client = await GetActorClient(plainSecret);

        var subjectToken = await GetClientSubjectToken();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = subjectToken.Reference,
            SubjectTokenType = TokenTypeIdentifier.AccessToken,
            Scope = [ScopeConstants.OpenId],
            Resource = ["https://localhost:5000/api"],
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidResource, processResult);
    }

    [Fact]
    public async Task Validate_ExtensionValidationFails_ExpectExtensionError()
    {
        // Arrange
        var extendedTokenExchangeRequestValidator = new Mock<IExtendedTokenExchangeRequestValidator>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(extendedTokenExchangeRequestValidator);
        });

        var validator = serviceProvider.GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var client = await GetActorClient(plainSecret);

        var subjectToken = await GetClientSubjectToken();

        var resourceClient = await GetResourceClient();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = subjectToken.Reference,
            SubjectTokenType = TokenTypeIdentifier.AccessToken,
            Scope = [ScopeConstants.OpenId],
            Resource = [resourceClient.ClientUri!],
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        const string error = "error";
        const string errorDescription = "error_description";
        extendedTokenExchangeRequestValidator
            .Setup(x =>
                x.Validate(
                    It.Is<ValidatedTokenExchangeRequest>(y =>
                        y.ClientId == client.Id
                        && y.RequestedTokenType == request.RequestedTokenType
                        && y.SubjectToken == request.SubjectToken
                        && y.SubjectTokenType == request.SubjectTokenType
                        && y.ActorToken == request.ActorToken
                        && y.ActorTokenType == request.ActorTokenType
                        && y.Resource.SequenceEqual(request.Resource)
                        && y.Scope.SequenceEqual(request.Scope)),
                    CancellationToken.None))
            .ReturnsAsync(new OAuthError(error, errorDescription))
            .Verifiable();

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.False(processResult.IsSuccess);
        Assert.Equal(error, processResult.Error!.Error);
        Assert.Equal(errorDescription, processResult.Error!.ErrorDescription);
        Assert.Equal(ResultCode.BadRequest, processResult.Error!.ResultCode);
        extendedTokenExchangeRequestValidator.Verify();
    }

    [Fact]
    public async Task Validate_DPoPProtectedSubjectToken_ExpectTokenExchangeValidatedRequest()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });

        var validator = serviceProvider.GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var client = await GetActorClient(plainSecret);

        var subjectToken = await GetClientSubjectToken();

        var resourceClient = await GetResourceClient();

        const string dPoPToken = "dpop_token";
        const string dPoPJkt = "dpop_jkt";
        dPoPService
            .Setup(x => x.ValidateDPoP(dPoPToken, client.Id, CancellationToken.None))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = true,
                DPoPJkt = dPoPJkt
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = subjectToken.Reference,
            SubjectTokenType = TokenTypeIdentifier.AccessToken,
            Scope = [ScopeConstants.OpenId],
            Resource = [resourceClient.ClientUri!],
            DPoP = dPoPToken,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.True(processResult.IsSuccess);
        Assert.Equal(request.RequestedTokenType, processResult.Value!.RequestedTokenType);
        Assert.NotNull(processResult.Value!.SubjectToken);
        Assert.Null(processResult.Value!.ActorToken);
        Assert.Equal(dPoPJkt, processResult.Value!.Jkt);
        Assert.Equal(request.Scope, processResult.Value!.Scope);
        Assert.Equal(request.Resource, processResult.Value!.Resource);
        dPoPService.Verify();
    }

    [Fact]
    public async Task Validate_SubjectTokenForIdToken_ExpectValidatedTokenExchangeValidatedRequest()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();

        var validator = serviceProvider.GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var client = await GetActorClient(plainSecret);

        var subjectToken = await GetConsentedGrantSubjectToken();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.IdToken,
            SubjectToken = subjectToken.Reference,
            SubjectTokenType = TokenTypeIdentifier.AccessToken,
            Scope = [ScopeConstants.OpenId],
            Resource = ["https://localhost:5000/api"],
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.True(processResult.IsSuccess);
        Assert.Equal(request.RequestedTokenType, processResult.Value!.RequestedTokenType);
        Assert.NotNull(processResult.Value!.SubjectToken);
        Assert.Null(processResult.Value!.ActorToken);
        Assert.Null(processResult.Value!.Jkt);
        Assert.Equal(request.Scope, processResult.Value!.Scope);
        Assert.Equal(request.Resource, processResult.Value!.Resource);
    }

    [Fact]
    public async Task Validate_DelegatedSubjectToken_ExpectValidatedTokenExchangeValidatedRequest()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();

        var validator = serviceProvider.GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var client = await GetActorClient(plainSecret);

        var actorToken = await GetConsentedGrantSubjectToken();
        var subjectToken = await GetClientSubjectToken();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = subjectToken.Reference,
            SubjectTokenType = TokenTypeIdentifier.AccessToken,
            ActorToken = actorToken.Reference,
            ActorTokenType = TokenTypeIdentifier.AccessToken,
            Scope = [ScopeConstants.OpenId],
            Resource = ["https://localhost:5000/api"],
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.True(processResult.IsSuccess);
        Assert.Equal(request.RequestedTokenType, processResult.Value!.RequestedTokenType);
        Assert.NotNull(processResult.Value!.SubjectToken);
        Assert.NotNull(processResult.Value!.ActorToken);
        Assert.Null(processResult.Value!.Jkt);
        Assert.Equal(request.Scope, processResult.Value!.Scope);
        Assert.Equal(request.Resource, processResult.Value!.Resource);
    }

    [Fact]
    public async Task Validate_DelegatedSubjectTokenWithMayAct_ExpectValidatedTokenExchangeValidatedRequest()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();

        var validator = serviceProvider.GetRequiredService<IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var client = await GetActorClient(plainSecret);
        var actorToken = await GetActorToken(client);

        var subjectToken = await GetConsentedGrantSubjectToken(subjectMayAct: actorToken.AuthorizationGrant.Subject);

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.TokenExchange,
            RequestedTokenType = TokenTypeIdentifier.AccessToken,
            SubjectToken = subjectToken.Reference,
            SubjectTokenType = TokenTypeIdentifier.AccessToken,
            ActorToken = actorToken.Reference,
            ActorTokenType = TokenTypeIdentifier.AccessToken,
            Scope = [ScopeConstants.OpenId],
            Resource = ["https://localhost:5000/api"],
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.True(processResult.IsSuccess);
        Assert.Equal(request.RequestedTokenType, processResult.Value!.RequestedTokenType);
        Assert.NotNull(processResult.Value!.SubjectToken);
        Assert.NotNull(processResult.Value!.ActorToken);
        Assert.Null(processResult.Value!.Jkt);
        Assert.Equal(request.Scope, processResult.Value!.Scope);
        Assert.Equal(request.Resource, processResult.Value!.Resource);
    }

    private async Task<Client> GetActorClient(string plainSecret)
    {
        var client = new Client("actor-web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        client.SetSecret(CryptographyHelper.HashPassword(plainSecret));
        client.GrantTypes.Add(await GetGrantType(GrantTypeConstants.TokenExchange));
        await AddEntity(client);
        return client;
    }

    private async Task<GrantAccessToken> GetActorToken(Client actorClient)
    {
        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationCodeGrant = new AuthorizationCodeGrant(session, actorClient, subjectIdentifier.Id, levelOfAssurance);

        var grantAccessToken = new GrantAccessToken(authorizationCodeGrant, "aud", DiscoveryDocument.Issuer, ScopeConstants.OpenId, 300);
        await AddEntity(grantAccessToken);

        return grantAccessToken;
    }

    private async Task<ClientAccessToken> GetClientSubjectToken(string? subjectActor = null, string? subjectMayAct = null)
    {
        var client = new Client("subject-web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);

        var openIdScope = await GetScope(ScopeConstants.OpenId);
        client.Scopes.Add(openIdScope);

        var accessToken = new ClientAccessToken(client, "aud", DiscoveryDocument.Issuer, ScopeConstants.OpenId, 300)
        {
            SubjectActor = subjectActor,
            SubjectMayAct = subjectMayAct
        };
        await AddEntity(accessToken);
        return accessToken;
    }

    private async Task<GrantAccessToken> GetGrantSubjectToken(string? subjectActor = null, string? subjectMayAct = null)
    {
        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("subject-web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationCodeGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);

        var accessToken = new GrantAccessToken(authorizationCodeGrant, "aud", DiscoveryDocument.Issuer, ScopeConstants.OpenId, 300)
        {
            SubjectActor = subjectActor,
            SubjectMayAct = subjectMayAct
        };
        await AddEntity(accessToken);
        return accessToken;
    }

    private async Task<GrantAccessToken> GetConsentedGrantSubjectToken(string? subjectActor = null, string? subjectMayAct = null)
    {
        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("subject-web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationCodeGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);

        var openIdScope = await GetScope(ScopeConstants.OpenId);
        client.Scopes.Add(openIdScope);

        var resourceClient = new Client("api", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            ClientUri = "https://localhost:5000/api"
        };
        resourceClient.Scopes.Add(openIdScope);
        await AddEntity(resourceClient);

        var openIdScopeConsent = new ScopeConsent(subjectIdentifier, client, openIdScope);
        var authorizationGrantScopeConsent = new AuthorizationGrantScopeConsent(openIdScopeConsent, authorizationCodeGrant, resourceClient.ClientUri);
        await AddEntity(authorizationGrantScopeConsent);

        var accessToken = new GrantAccessToken(authorizationCodeGrant, "aud", DiscoveryDocument.Issuer, ScopeConstants.OpenId, 300)
        {
            SubjectActor = subjectActor,
            SubjectMayAct = subjectMayAct
        };
        await AddEntity(accessToken);
        return accessToken;
    }

    private async Task<Client> GetResourceClient()
    {
        var client = new Client("web-api", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            ClientUri = "https://localhost:5001/api"
        };

        var openIdScope = await GetScope(ScopeConstants.OpenId);
        client.Scopes.Add(openIdScope);

        await AddEntity(client);
        await SaveChangesAsync();
        return client;
    }
}