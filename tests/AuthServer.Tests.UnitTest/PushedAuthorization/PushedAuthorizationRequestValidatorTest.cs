using AuthServer.Authentication.Models;
using AuthServer.Authorization;
using AuthServer.Authorization.Abstractions;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Helpers;
using AuthServer.PushedAuthorization;
using AuthServer.RequestAccessors.PushedAuthorization;
using AuthServer.Tests.Core;
using AuthServer.TokenDecoders;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;
using ProofKeyForCodeExchangeHelper = AuthServer.Tests.Core.ProofKeyForCodeExchangeHelper;

namespace AuthServer.Tests.UnitTest.PushedAuthorization;

public class PushedAuthorizationRequestValidatorTest : BaseUnitTest
{
    public PushedAuthorizationRequestValidatorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task Validate_NoClientAuthentication_ExpectMultipleOrNoneClientMethod()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var request = new PushedAuthorizationRequest();

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.MultipleOrNoneClientMethod, processResult.Error);
    }

    [Fact]
    public async Task Validate_InvalidClientAuthentication_ExpectInvalidClient()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, "invalid_id", "invalid_secret")
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.InvalidClient, processResult.Error);
    }

    [Fact]
    public async Task Validate_RequireRequestObjectWithEmptyRequestObject_ExpectRequestRequiredAsRequestObject()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        client.RequireSignedRequestObject = true;
        await SaveChangesAsync();

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.RequestRequiredAsRequestObject, processResult.Error);
    }

    [Fact]
    public async Task Validate_InvalidRequestObject_ExpectInvalidRequest()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            RequestObject = "invalid_request_object"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.InvalidRequest, processResult.Error);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task Validate_InvalidState_ExpectInvalidState(string? state)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            State = state
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.InvalidState, processResult.Error);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task Validate_MultipleRegisteredRedirectUrisWithInvalidRedirectUri_ExpectInvalidRedirectUri(string? redirectUri)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        client.RedirectUris.Add(new RedirectUri("https://webapp.authserver.dk/other-callback", client));
        await SaveChangesAsync();

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            State = CryptographyHelper.GetRandomString(16),
            RedirectUri = redirectUri
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.InvalidRedirectUri, processResult.Error);
    }

    [Fact]
    public async Task Validate_InvalidRedirectUri_ExpectUnauthorizedRedirectUri()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            State = CryptographyHelper.GetRandomString(16),
            RedirectUri = "invalid_redirect_uri"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.UnauthorizedRedirectUri, processResult.Error);
    }

    [Fact]
    public async Task Validate_InvalidResponseMode_ExpectInvalidResponseMode()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            State = CryptographyHelper.GetRandomString(16),
            ResponseMode = "invalid_response_mode"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.InvalidResponseMode, processResult.Error);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("invalid_response_type")]
    public async Task Validate_InvalidResponseType_ExpectInvalidResponseType(string? responseType)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = responseType
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.InvalidResponseType, processResult.Error);
    }

    [Fact]
    public async Task Validate_UnauthorizedGrantType_ExpectUnauthorizedResponseType()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        client.GrantTypes.Clear();
        await SaveChangesAsync();

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.UnauthorizedResponseType, processResult.Error);
    }

    [Fact]
    public async Task Validate_InvalidDisplay_ExpectInvalidDisplay()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Display = "invalid_display"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.InvalidDisplay, processResult.Error);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task Validate_InvalidNonce_ExpectInvalidNonce(string? nonce)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = nonce
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.InvalidNonce, processResult.Error);
    }

    [Fact]
    public async Task Validate_DuplicateNonce_ExpectReplayNonce()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var authenticationContextReference = await GetAuthenticationContextReference(LevelOfAssuranceStrict);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, authenticationContextReference);
        var nonceValue = Guid.NewGuid().ToString();
        var nonce = new Nonce(nonceValue, nonceValue.Sha256(), authorizationGrant);
        await AddEntity(nonce);

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = nonceValue
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.ReplayNonce, processResult.Error);
    }

    [Fact]
    public async Task Validate_InvalidCodeChallengeMethod_ExpectInvalidCodeChallengeMethod()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = "invalid_code_challenge_method"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.InvalidCodeChallengeMethod, processResult.Error);
    }

    [Fact]
    public async Task Validate_InvalidCodeChallenge_ExpectInvalidCodeChallenge()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = "invalid_code_challenge"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.InvalidCodeChallenge, processResult.Error);
    }

    [Fact]
    public async Task Validate_InvalidScope_ExpectInvalidScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        var proofKeyForCodeExchange = ProofKeyForCodeExchangeHelper.GetProofKeyForCodeExchange();

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = proofKeyForCodeExchange.CodeChallenge
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.InvalidOpenIdScope, processResult.Error);
    }

    [Fact]
    public async Task Validate_UnauthorizedScope_ExpectUnauthorizedScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        client.Scopes.Clear();
        await SaveChangesAsync();
        var proofKeyForCodeExchange = ProofKeyForCodeExchangeHelper.GetProofKeyForCodeExchange();

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = proofKeyForCodeExchange.CodeChallenge,
            Scope = [ScopeConstants.OpenId]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.UnauthorizedScope, processResult.Error);
    }

    [Fact]
    public async Task Validate_EmptyResource_ExpectInvalidTarget()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        var proofKeyForCodeExchange = ProofKeyForCodeExchangeHelper.GetProofKeyForCodeExchange();

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = proofKeyForCodeExchange.CodeChallenge,
            Scope = [ScopeConstants.OpenId]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.InvalidResource, processResult.Error);
    }

    [Fact]
    public async Task Validate_InvalidResource_ExpectInvalidTarget()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        var proofKeyForCodeExchange = ProofKeyForCodeExchangeHelper.GetProofKeyForCodeExchange();

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = proofKeyForCodeExchange.CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = ["invalid_resource"]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.InvalidResource, processResult.Error);
    }

    [Fact]
    public async Task Validate_InvalidMaxAge_ExpectInvalidMaxAge()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        var proofKeyForCodeExchange = ProofKeyForCodeExchangeHelper.GetProofKeyForCodeExchange();

        var resource = await GetResource();

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = proofKeyForCodeExchange.CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!],
            MaxAge = "invalid_max_age"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.InvalidMaxAge, processResult.Error);
    }

    [Fact]
    public async Task Validate_InvalidIdTokenHint_ExpectInvalidIdTokenHint()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        var proofKeyForCodeExchange = ProofKeyForCodeExchangeHelper.GetProofKeyForCodeExchange();

        var resource = await GetResource();

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = proofKeyForCodeExchange.CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!],
            IdTokenHint = "invalid_token"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.InvalidIdTokenHint, processResult.Error);
    }

    [Fact]
    public async Task Validate_InvalidPrompt_ExpectInvalidPrompt()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        var proofKeyForCodeExchange = ProofKeyForCodeExchangeHelper.GetProofKeyForCodeExchange();

        var resource = await GetResource();

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = proofKeyForCodeExchange.CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!],
            Prompt = "invalid_prompt"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.InvalidPrompt, processResult.Error);
    }

    [Fact]

    public async Task Validate_InvalidAcrValues_ExpectInvalidAcrValues()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        var proofKeyForCodeExchange = ProofKeyForCodeExchangeHelper.GetProofKeyForCodeExchange();

        var resource = await GetResource();

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = proofKeyForCodeExchange.CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!],
            AcrValues = ["invalid_acr_value"]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(PushedAuthorizationError.InvalidAcrValues, processResult.Error);
    }

    [Fact]
    public async Task Validate_MinimalRequest_ExpectValidatedRequest()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        var proofKeyForCodeExchange = ProofKeyForCodeExchangeHelper.GetProofKeyForCodeExchange();

        var resource = await GetResource();

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = proofKeyForCodeExchange.CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.True(processResult.IsSuccess);
        Assert.Null(processResult.Value!.LoginHint);
        Assert.Null(processResult.Value!.IdTokenHint);
        Assert.Null(processResult.Value!.Display);
        Assert.Equal(request.ResponseType, processResult.Value!.ResponseType);
        Assert.Null(processResult.Value!.ResponseMode);
        Assert.Equal(request.CodeChallenge, processResult.Value!.CodeChallenge);
        Assert.Equal(request.CodeChallengeMethod, processResult.Value!.CodeChallengeMethod);
        Assert.Equal(request.Scope, processResult.Value!.Scope);
        Assert.Empty(processResult.Value!.AcrValues);
        Assert.Equal(client.Id, processResult.Value!.ClientId);
        Assert.Null(processResult.Value!.MaxAge);
        Assert.Equal(request.Nonce, processResult.Value!.Nonce);
        Assert.Equal(request.State, processResult.Value!.State);
        Assert.Null(request.RedirectUri);
    }

    [Fact]
    public async Task Validate_MinimalRequestObject_ExpectValidatedRequest()
    {
        // Arrange
        var secureRequestService = new Mock<ISecureRequestService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(secureRequestService);
        });
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        var proofKeyForCodeExchange = ProofKeyForCodeExchangeHelper.GetProofKeyForCodeExchange();

        var resource = await GetResource();

        const string requestObject = "requestObject";
        var authorizeRequestDto = new AuthorizeRequestDto
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = CryptographyHelper.GetRandomString(16),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = proofKeyForCodeExchange.CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!]
        };

        secureRequestService
            .Setup(x =>
                x.GetRequestByObject(requestObject, client.Id, ClientTokenAudience.PushedAuthorizeEndpoint, CancellationToken.None))
            .ReturnsAsync(authorizeRequestDto)
            .Verifiable();

        var request = new PushedAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            RequestObject = requestObject
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        secureRequestService.Verify();

        Assert.True(processResult.IsSuccess);
        Assert.Null(processResult.Value!.LoginHint);
        Assert.Null(processResult.Value!.IdTokenHint);
        Assert.Null(processResult.Value!.Display);
        Assert.Equal(authorizeRequestDto.ResponseType, processResult.Value!.ResponseType);
        Assert.Null(processResult.Value!.ResponseMode);
        Assert.Equal(authorizeRequestDto.CodeChallenge, processResult.Value!.CodeChallenge);
        Assert.Equal(authorizeRequestDto.CodeChallengeMethod, processResult.Value!.CodeChallengeMethod);
        Assert.Equal(authorizeRequestDto.Scope, processResult.Value!.Scope);
        Assert.Empty(processResult.Value!.AcrValues);
        Assert.Equal(client.Id, processResult.Value!.ClientId);
        Assert.Null(processResult.Value!.MaxAge);
        Assert.Equal(authorizeRequestDto.Nonce, processResult.Value!.Nonce);
        Assert.Equal(authorizeRequestDto.State, processResult.Value!.State);
        Assert.Null(authorizeRequestDto.RedirectUri);
    }

    private async Task<Client> GetClient(string plainSecret)
    {
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        client.RedirectUris.Add(new RedirectUri("https://webapp.authserver.dk/callback", client));
        client.GrantTypes.Add(await GetGrantType(GrantTypeConstants.AuthorizationCode));
        client.Scopes.Add(await GetScope(ScopeConstants.OpenId));
        var hashedSecret = CryptographyHelper.HashPassword(plainSecret);
        client.SetSecret(hashedSecret);
        await AddEntity(client);
        return client;
    }

    private async Task<Client> GetResource()
    {
        var resource = new Client("weather-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic)
        {
            ClientUri = "https://weather.authserver.dk"
        };
        resource.Scopes.Add(await GetScope(ScopeConstants.OpenId));
        await AddEntity(resource);

        return resource;
    }
}