using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Authorize;
using AuthServer.Authorize.Abstractions;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Helpers;
using AuthServer.Repositories.Abstractions;
using AuthServer.Tests.Core;
using AuthServer.TokenDecoders;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;
using ProofKeyGenerator = AuthServer.Tests.Core.ProofKeyGenerator;

namespace AuthServer.Tests.UnitTest.Authorize;

public class AuthorizeRequestValidatorTest : BaseUnitTest
{
    public AuthorizeRequestValidatorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Theory]
    [InlineData("")]
    [InlineData("invalid_client_id")]
    public async Task Validate_InvalidClientId_ExpectInvalidClient(string clientId)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService <
                        IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var request = new AuthorizeRequest
        {
            ClientId = clientId
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidClient, processResult);
    }

    [Fact]
    public async Task Validate_GivenRequestAndRequestUri_ExpectInvalidRequestAndRequestUri()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService <
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            RequestUri = "uri",
            RequestObject = "object"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidRequestAndRequestUri, processResult);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task Validate_RequireSignedRequestWithEmptyRequestAndRequestUri_ExpectRequestOrRequestUriRequiredAsRequestObject(bool clientRequires, bool serverRequires)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        DiscoveryDocument.RequireSignedRequestObject = serverRequires;

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            RequireSignedRequestObject = clientRequires
        };
        await AddEntity(client);

        var request = new AuthorizeRequest
        {
            ClientId = client.Id
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.RequestOrRequestUriRequiredAsRequestObject, processResult);
    }

    [Theory]
    [InlineData(true, false,  null)]
    [InlineData(false, true, "")]
    [InlineData(true, true, "value")]
    public async Task Validate_RequirePushedAuthorizationWithEmptyRequestUri_ExpectRequestUriRequiredAsPushedAuthorizationRequest(bool clientRequires, bool serverRequires, string? requestUri)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        DiscoveryDocument.RequirePushedAuthorizationRequests = serverRequires;

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            RequirePushedAuthorizationRequests = clientRequires
        };
        await AddEntity(client);

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            RequestUri = requestUri
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.RequestUriRequiredAsPushedAuthorizationRequest, processResult);
    }

    [Fact]
    public async Task Validate_InvalidRequestUriFromPushedAuthorization_ExpectInvalidOrExpireRequestUri()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            RequestUri = $"{RequestUriConstants.RequestUriPrefix}invalid_value"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidOrExpiredRequestUri, processResult);
    }

    [Fact]
    public async Task Validate_RequestFromPushedAuthorizationAndRequiresInteractionWithRedirectToInteraction_ExpectInteractionWithReusedRequestUri()
    {
        // Arrange
        var secureRequestService = new Mock<ISecureRequestService>();
        var authorizeInteractionService = new Mock<IAuthorizeInteractionService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(secureRequestService);
            services.AddScopedMock(authorizeInteractionService);
        });
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();
        const string requestUri = $"{RequestUriConstants.RequestUriPrefix}reference";

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            RequestUri = requestUri
        };

        var authorizeRequestDto = new AuthorizeRequestDto
        {
            ClientId = client.Id
        };

        secureRequestService
            .Setup(x => x.GetRequestByPushedRequest(requestUri, client.Id, CancellationToken.None))
            .ReturnsAsync(authorizeRequestDto)
            .Verifiable();

        authorizeInteractionService
            .Setup(x => x.GetInteractionResult(It.IsAny<AuthorizeRequest>(), CancellationToken.None))
            .ReturnsAsync(InteractionResult.LoginRedirectResult)
            .Verifiable();

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);
        await IdentityContext.SaveChangesAsync();

        // Assert
        authorizeInteractionService.Verify();
        Assert.Equal(AuthorizeError.LoginRequired.Error, processResult.Error!.Error);
        Assert.Equal(AuthorizeError.LoginRequired.ErrorDescription, processResult.Error!.ErrorDescription);
        Assert.Equal(AuthorizeError.LoginRequired.ResultCode, processResult.Error!.ResultCode);

        Assert.IsType<AuthorizeInteractionError>(processResult.Error);
        var authorizeInteractionError = (processResult.Error as AuthorizeInteractionError)!;
        Assert.Equal(request.ClientId, authorizeInteractionError.ClientId);

        Assert.Equal(request.RequestUri, authorizeInteractionError.RequestUri);
    }

    [Fact]
    public async Task Validate_ValidRequestUriFromPushedAuthorization_ExpectAuthorizeValidatedRequest()
    {
        // Arrange
        var secureRequestService = new Mock<ISecureRequestService>();
        var authorizeInteractionService = new Mock<IAuthorizeInteractionService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(secureRequestService);
            services.AddScopedMock(authorizeInteractionService);
        });
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);

        var resource = await GetResource();

        const string requestUri = $"{RequestUriConstants.RequestUriPrefix}valid_value";
        const string subjectIdentifier = "subjectIdentifier";
        const string authorizationGrantId = "authorizationGrantId";

        var authorizeRequestDto = new AuthorizeRequestDto
        {
            ResponseMode = ResponseModeConstants.FormPost,
            CodeChallenge = CryptographyHelper.GetRandomString(16),
            Scope = [ScopeConstants.OpenId],
            AcrValues = [LevelOfAssuranceLow],
            ClientId = client.Id,
            Nonce = CryptographyHelper.GetRandomString(16),
            RedirectUri = "https://webapp.authserver.dk/callback",
            Resource = [resource.ClientUri!]
        };

        secureRequestService
            .Setup(x => x.GetRequestByPushedRequest(requestUri, client.Id, CancellationToken.None))
            .ReturnsAsync(authorizeRequestDto)
            .Verifiable();

        authorizeInteractionService
            .Setup(x =>
                x.GetInteractionResult(It.Is<AuthorizeRequest>(y =>
                    y.ResponseMode == authorizeRequestDto.ResponseMode &&
                    y.CodeChallenge == authorizeRequestDto.CodeChallenge &&
                    y.Scope == authorizeRequestDto.Scope &&
                    y.AcrValues == authorizeRequestDto.AcrValues &&
                    y.ClientId == authorizeRequestDto.ClientId &&
                    y.Nonce == authorizeRequestDto.Nonce &&
                    y.RedirectUri == authorizeRequestDto.RedirectUri &&
                    y.Resource == authorizeRequestDto.Resource &&
                    y.RequestUri == requestUri), CancellationToken.None))
            .ReturnsAsync(InteractionResult.Success(subjectIdentifier, authorizationGrantId))
            .Verifiable();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            RequestUri = requestUri
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        secureRequestService.Verify();
        authorizeInteractionService.Verify();

        Assert.Equal(authorizationGrantId, processResult.Value!.AuthorizationGrantId);
        Assert.Equal(authorizeRequestDto.ResponseMode, processResult.Value!.ResponseMode);
        Assert.Equal(authorizeRequestDto.CodeChallenge, processResult.Value!.CodeChallenge);
        Assert.Equal(authorizeRequestDto.Scope, processResult.Value!.Scope);
        Assert.Equal(authorizeRequestDto.AcrValues, processResult.Value!.AcrValues);
        Assert.Equal(authorizeRequestDto.ClientId, processResult.Value!.ClientId);
        Assert.Equal(authorizeRequestDto.Nonce, processResult.Value!.Nonce);
        Assert.Equal(authorizeRequestDto.RedirectUri, processResult.Value!.RedirectUri);
        Assert.Equal(authorizeRequestDto.Resource, processResult.Value!.Resource);
        Assert.Equal(requestUri, processResult.Value!.RequestUri);
    }

    [Fact]
    public async Task Validate_InvalidRequestUriFromClient_ExpectInvalidRequestUri()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            RequestUri = "invalid_value"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidRequestUri, processResult);
    }

    [Fact]
    public async Task Validate_ClientIsUnauthorizedForRequestUri_ExpectUnauthorizedRequestUri()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            RequestUri = "https://webapp.authserver.dk/request#4567kebab"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.UnauthorizedRequestUri, processResult);
    }

    [Fact]
    public async Task Validate_RequestUriPointsToInvalidRequestObject_ExpectInvalidRequestObjectFromRequestUri()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(new Mock<ISecureRequestService>());
        });
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var requestUri = new RequestUri("https://webapp.authserver.dk/request", client);
        await AddEntity(requestUri);

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            RequestUri = $"{requestUri.Uri}#3790kebab"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidRequestObjectFromRequestUri, processResult);
    }

    [Fact]
    public async Task Validate_InvalidRequestObject_ExpectInvalidRequest()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(new Mock<ISecureRequestService>());
        });
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            RequestObject = "invalid_request"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidRequest, processResult);
    }

    [Fact]
    public async Task Validate_InvalidState_ExpectInvalidState()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);

        var request = new AuthorizeRequest
        {
            ClientId = client.Id
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidState, processResult);
    }

    [Fact]
    public async Task Validate_EmptyRedirectUriWithMultipleRegisteredRedirectUris_ExpectInvalidRedirectUri()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var redirectUriOne = new RedirectUri("https://webapp.authserver.dk/callback-one", client);
        var redirectUriTwo = new RedirectUri("https://webapp.authserver.dk/callback-two", client);
        await AddEntity(redirectUriOne);
        await AddEntity(redirectUriTwo);

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16)
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidRedirectUri, processResult);
    }

    [Fact]
    public async Task Validate_EmptyRedirectUriWithZeroRegisteredRedirectUris_ExpectInvalidRedirectUri()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClientWithoutRedirectUri();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16)
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidRedirectUri, processResult);
    }

    [Fact]
    public async Task Validate_ClientIsUnauthorizedForRedirectUri_ExpectUnauthorizedRedirectUri()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            RedirectUri = "https://webapp.authserver.dk/invalid"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.UnauthorizedRedirectUri, processResult);
    }

    [Fact]
    public async Task Validate_InvalidResponseMode_ExpectInvalidResponseMode()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseMode = "invalid_response_mode"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidResponseMode, processResult);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("invalid_response_type")]
    public async Task Validate_InvalidResponseType_ExpectInvalidResponseType(string? responseType)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = responseType
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidResponseType, processResult);
    }

    [Fact]
    public async Task Validate_ClientIsUnauthorizedForAuthorizationCode_ExpectUnauthorizedResponseType()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClientWithoutGrantType();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.UnauthorizedResponseType, processResult);
    }

    [Fact]
    public async Task Validate_InvalidDisplay_ExpectInvalidDisplay()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Display = "invalid_display"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidDisplay, processResult);
    }

    [Fact]
    public async Task Validate_EmptyNonce_ExpectInvalidNonce()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidNonce, processResult);
    }

    [Fact]
    public async Task Validate_NonceIsNotUnique_ExpectReplayNonce()
    {
        // Arrange
        var nonceRepository = new Mock<INonceRepository>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(nonceRepository);
        });
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var nonce = CryptographyHelper.GetRandomString(16);
        nonceRepository
            .Setup(x => x.IsNonceReplay(nonce, CancellationToken.None))
            .ReturnsAsync(true)
            .Verifiable();

        var client = await GetClient();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = nonce
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        nonceRepository.Verify();
        Assert.Equal(AuthorizeError.ReplayNonce, processResult);
    }

    [Fact]
    public async Task Validate_InvalidCodeChallengeMethod_ExpectInvalidCodeChallengeMethod()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = CryptographyHelper.GetRandomString(16),
            CodeChallengeMethod = "invalid_code_challenge_method"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidCodeChallengeMethod, processResult);
    }

    [Fact]
    public async Task Validate_InvalidCodeChallenge_ExpectInvalidCodeChallenge()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = CryptographyHelper.GetRandomString(16),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = "invalid_code_challenge"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidCodeChallenge, processResult);
    }

    [Fact]
    public async Task Validate_ScopeDoesNotContainOpenId_ExpectInvalidOpenIdScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = CryptographyHelper.GetRandomString(16),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = ProofKeyGenerator.GetProofKeyForCodeExchange().CodeChallenge
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidOpenIdScope, processResult);
    }

    [Fact]
    public async Task Validate_ClientIsUnauthorizedForOpenIdScope_ExpectUnauthorizedScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClientWithoutScope();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = CryptographyHelper.GetRandomString(16),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = ProofKeyGenerator.GetProofKeyForCodeExchange().CodeChallenge,
            Scope = [ScopeConstants.OpenId]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.UnauthorizedScope, processResult);
    }

    [Fact]
    public async Task Validate_EmptyResource_ExpectInvalidResource()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = CryptographyHelper.GetRandomString(16),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = ProofKeyGenerator.GetProofKeyForCodeExchange().CodeChallenge,
            Scope = [ScopeConstants.OpenId]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidResource, processResult);
    }

    [Fact]
    public async Task Validate_InvalidResource_ExpectInvalidResource()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = CryptographyHelper.GetRandomString(16),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = ProofKeyGenerator.GetProofKeyForCodeExchange().CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = ["invalid_target"]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidResource, processResult);
    }

    [Fact]
    public async Task Validate_InvalidMaxAge_ExpectInvalidMaxAge()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();
        var resource = await GetResource();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = CryptographyHelper.GetRandomString(16),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = ProofKeyGenerator.GetProofKeyForCodeExchange().CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!],
            MaxAge = "-1"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidMaxAge, processResult);
    }

    [Fact]
    public async Task Validate_InvalidIdTokenHint_ExpectInvalidIdTokenHint()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();
        var resource = await GetResource();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = CryptographyHelper.GetRandomString(16),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = ProofKeyGenerator.GetProofKeyForCodeExchange().CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!],
            IdTokenHint = "invalid_id_token"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidIdTokenHint, processResult);
    }

    [Fact]
    public async Task Validate_InvalidPrompt_ExpectInvalidPrompt()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();
        var resource = await GetResource();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = CryptographyHelper.GetRandomString(16),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = ProofKeyGenerator.GetProofKeyForCodeExchange().CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!],
            Prompt = "invalid_prompt"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidPrompt, processResult);
    }

    [Fact]
    public async Task Validate_InvalidAcrValues_ExpectInvalidAcrValues()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();
        var resource = await GetResource();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = CryptographyHelper.GetRandomString(16),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = ProofKeyGenerator.GetProofKeyForCodeExchange().CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!],
            AcrValues = ["invalid_acr_value"]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidAcrValues, processResult);
    }

    [Theory]
    [InlineData("", null)]
    [InlineData(null, null)]
    [InlineData("invalid_grant_management_action", null)]
    [InlineData("", "grant_id")]
    [InlineData(null, "grant_id")]
    [InlineData(GrantManagementActionConstants.Create, "grant_id")]
    [InlineData(GrantManagementActionConstants.Replace, "")]
    [InlineData(GrantManagementActionConstants.Replace, null)]
    [InlineData(GrantManagementActionConstants.Merge, "")]
    [InlineData(GrantManagementActionConstants.Merge, null)]
    public async Task Validate_GrantManagementActionWithGrantId_ExpectInvalidGrantManagement(string? grantManagementAction, string? grantId)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        DiscoveryDocument.GrantManagementActionRequired = true;

        var client = await GetClient();
        var resource = await GetResource();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = CryptographyHelper.GetRandomString(16),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = ProofKeyGenerator.GetProofKeyForCodeExchange().CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!],
            GrantManagementAction = grantManagementAction,
            GrantId = grantId
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidGrantManagement, processResult);
    }

    [Fact]
    public async Task Validate_InvalidGrantId_ExpectInvalidGrantId()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();
        var resource = await GetResource();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = CryptographyHelper.GetRandomString(16),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = ProofKeyGenerator.GetProofKeyForCodeExchange().CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!],
            GrantManagementAction = GrantManagementActionConstants.Replace,
            GrantId = "invalid_grant_id"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidGrantId, processResult);
    }

    [Fact]
    public async Task Validate_InvalidDPoPJkt_ExpectInvalidDPoPJkt()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();
        client.RequireDPoPBoundAccessTokens = true;
        await SaveChangesAsync();
        var resource = await GetResource();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = CryptographyHelper.GetRandomString(16),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = ProofKeyGenerator.GetProofKeyForCodeExchange().CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(AuthorizeError.InvalidDPoPJkt, processResult);
    }

    [Fact]
    public async Task Validate_RequiresInteractionWithoutRedirectToInteraction_ExpectInteraction()
    {
        // Arrange
        var authorizeInteractionService = new Mock<IAuthorizeInteractionService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizeInteractionService);
        });
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();
        var resource = await GetResource();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = CryptographyHelper.GetRandomString(16),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = ProofKeyGenerator.GetProofKeyForCodeExchange().CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!]
        };

        authorizeInteractionService
            .Setup(x => x.GetInteractionResult(request, CancellationToken.None))
            .ReturnsAsync(InteractionResult.LoginErrorResult)
            .Verifiable();

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        authorizeInteractionService.Verify();

        Assert.Equal(AuthorizeError.LoginRequired.Error, processResult.Error!.Error);
        Assert.Equal(AuthorizeError.LoginRequired.ErrorDescription, processResult.Error!.ErrorDescription);
        Assert.Equal(AuthorizeError.LoginRequired.ResultCode, processResult.Error!.ResultCode);
        Assert.IsNotType<PersistRequestUriError>(processResult.Error);
    }

    [Fact]
    public async Task Validate_RequiresInteractionWithRedirectToInteraction_ExpectPersistRequestUri()
    {
        // Arrange
        var authorizeInteractionService = new Mock<IAuthorizeInteractionService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizeInteractionService);
        });
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();
        var resource = await GetResource();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = CryptographyHelper.GetRandomString(16),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = ProofKeyGenerator.GetProofKeyForCodeExchange().CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!]
        };

        authorizeInteractionService
            .Setup(x => x.GetInteractionResult(request, CancellationToken.None))
            .ReturnsAsync(InteractionResult.LoginRedirectResult)
            .Verifiable();

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        authorizeInteractionService.Verify();

        Assert.Equal(AuthorizeError.LoginRequired.Error, processResult.Error!.Error);
        Assert.Equal(AuthorizeError.LoginRequired.ErrorDescription, processResult.Error!.ErrorDescription);
        Assert.Equal(AuthorizeError.LoginRequired.ResultCode, processResult.Error!.ResultCode);

        Assert.IsType<PersistRequestUriError>(processResult.Error);
        Assert.Equal(((PersistRequestUriError)processResult.Error).AuthorizeRequest, request);
    }

    [Fact]
    public async Task Validate_MinimalValidRequestWithResponseTypeCode_ExpectAuthorizeValidatedRequest()
    {
        // Arrange
        var authorizeInteractionService = new Mock<IAuthorizeInteractionService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizeInteractionService);
        });
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();
        var resource = await GetResource();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = CryptographyHelper.GetRandomString(16),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = ProofKeyGenerator.GetProofKeyForCodeExchange().CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!]
        };

        const string subjectIdentifier = "subjectIdentifier";
        const string authorizationGrantId = "authorizationGrantId";
        authorizeInteractionService
            .Setup(x => x.GetInteractionResult(request, CancellationToken.None))
            .ReturnsAsync(InteractionResult.Success(subjectIdentifier, authorizationGrantId))
            .Verifiable();

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        authorizeInteractionService.Verify();

        Assert.Equal(authorizationGrantId, processResult.Value!.AuthorizationGrantId);
        Assert.Equal(request.ResponseMode, processResult.Value!.ResponseMode);
        Assert.Equal(request.CodeChallenge, processResult.Value!.CodeChallenge);
        Assert.Equal(request.CodeChallengeMethod, processResult.Value!.CodeChallengeMethod);
        Assert.Equal(request.Scope, processResult.Value!.Scope);
        Assert.Equal(request.Resource, processResult.Value!.Resource);
        Assert.Equal(request.ClientId, processResult.Value!.ClientId);
        Assert.Equal(request.Nonce, processResult.Value!.Nonce);
        Assert.Equal(request.RedirectUri, processResult.Value!.RedirectUri);
        Assert.Equal(request.ResponseType, processResult.Value!.ResponseType);
        Assert.Null(processResult.Value!.RequestUri);
    }

    [Fact]
    public async Task Validate_MinimalRequestWithResponseTypeNone_ExpectValidatedRequest()
    {
        // Arrange
        var authorizeInteractionService = new Mock<IAuthorizeInteractionService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizeInteractionService);
        });
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();
        var resource = await GetResource();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.None,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!]
        };

        const string subjectIdentifier = "subjectIdentifier";
        const string authorizationGrantId = "authorizationGrantId";
        authorizeInteractionService
            .Setup(x => x.GetInteractionResult(request, CancellationToken.None))
            .ReturnsAsync(InteractionResult.Success(subjectIdentifier, authorizationGrantId))
            .Verifiable();

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        authorizeInteractionService.Verify();

        Assert.Equal(authorizationGrantId, processResult.Value!.AuthorizationGrantId);
        Assert.Equal(request.ResponseMode, processResult.Value!.ResponseMode);
        Assert.Equal(request.CodeChallenge, processResult.Value!.CodeChallenge);
        Assert.Equal(request.CodeChallengeMethod, processResult.Value!.CodeChallengeMethod);
        Assert.Equal(request.Scope, processResult.Value!.Scope);
        Assert.Equal(request.Resource, processResult.Value!.Resource);
        Assert.Equal(request.ClientId, processResult.Value!.ClientId);
        Assert.Equal(request.Nonce, processResult.Value!.Nonce);
        Assert.Equal(request.RedirectUri, processResult.Value!.RedirectUri);
        Assert.Equal(request.ResponseType, processResult.Value!.ResponseType);
        Assert.Null(processResult.Value!.RequestUri);
    }

    [Fact]
    public async Task Validate_FullValidatedRequest_ExpectAuthorizeValidatedRequest()
    {
        // Arrange
        var authorizeInteractionService = new Mock<IAuthorizeInteractionService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizeInteractionService);
        });
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();
        var resource = await GetResource();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            State = CryptographyHelper.GetRandomString(16),
            ResponseType = ResponseTypeConstants.Code,
            Nonce = CryptographyHelper.GetRandomString(16),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = ProofKeyGenerator.GetProofKeyForCodeExchange().CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            AcrValues = [LevelOfAssuranceSubstantial],
            Display = DisplayConstants.Page,
            MaxAge = "300",
            Prompt = PromptConstants.None,
            RedirectUri = client.RedirectUris.Single().Uri,
            ResponseMode = ResponseModeConstants.FormPost,
            DPoPJkt = CryptographyHelper.GetRandomString(16),
            Resource = [resource.ClientUri!]
        };

        const string subjectIdentifier = "subjectIdentifier";
        const string authorizationGrantId = "authorizationGrantId";
        authorizeInteractionService
            .Setup(x => x.GetInteractionResult(request, CancellationToken.None))
            .ReturnsAsync(InteractionResult.Success(subjectIdentifier, authorizationGrantId))
            .Verifiable();

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        authorizeInteractionService.Verify();

        Assert.Equal(authorizationGrantId, processResult.Value!.AuthorizationGrantId);
        Assert.Equal(request.ResponseMode, processResult.Value!.ResponseMode);
        Assert.Equal(request.CodeChallenge, processResult.Value!.CodeChallenge);
        Assert.Equal(request.CodeChallengeMethod, processResult.Value!.CodeChallengeMethod);
        Assert.Equal(request.Scope, processResult.Value!.Scope);
        Assert.Equal(request.AcrValues, processResult.Value!.AcrValues);
        Assert.Equal(request.Resource, processResult.Value!.Resource);
        Assert.Equal(request.ClientId, processResult.Value!.ClientId);
        Assert.Equal(request.Nonce, processResult.Value!.Nonce);
        Assert.Equal(request.RedirectUri, processResult.Value!.RedirectUri);
        Assert.Equal(request.ResponseType, processResult.Value!.ResponseType);
        Assert.Equal(request.DPoPJkt, processResult.Value!.DPoPJkt);
        Assert.Null(processResult.Value!.RequestUri);
    }

    [Fact]
    public async Task Validate_ValidRequestObjectFromRequestUri_ExpectAuthorizeValidatedRequest()
    {
        // Arrange
        var secureRequestService = new Mock<ISecureRequestService>();
        var authorizeInteractionService = new Mock<IAuthorizeInteractionService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(secureRequestService);
            services.AddScopedMock(authorizeInteractionService);
        });
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();
        var requestUri = new RequestUri("https://webapp.authserver.dk/request", client);
        await AddEntity(requestUri);

        var resource = await GetResource();

        var givenRequestUri = $"{requestUri.Uri}#1234";
        const string subjectIdentifier = "subjectIdentifier";
        const string authorizationGrantId = "authorizationGrantId";

        var authorizeRequestDto = new AuthorizeRequestDto
        {
            ResponseMode = ResponseModeConstants.FormPost,
            CodeChallenge = ProofKeyGenerator.GetProofKeyForCodeExchange().CodeChallenge,
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            ResponseType = ResponseTypeConstants.Code,
            Scope = [ScopeConstants.OpenId],
            AcrValues = [LevelOfAssuranceLow],
            ClientId = client.Id,
            Nonce = CryptographyHelper.GetRandomString(16),
            State = CryptographyHelper.GetRandomString(16),
            RedirectUri = client.RedirectUris.Single().Uri,
            DPoPJkt = CryptographyHelper.GetRandomString(16),
            Resource = [resource.ClientUri!]
        };

        secureRequestService
            .Setup(x =>
                x.GetRequestByReference(
                    It.Is<Uri>(y => y.AbsoluteUri == givenRequestUri),
                    client.Id,
                    ClientTokenAudience.AuthorizationEndpoint,
                    CancellationToken.None)
                )
            .ReturnsAsync(authorizeRequestDto)
            .Verifiable();

        authorizeInteractionService
            .Setup(x =>
                x.GetInteractionResult(It.Is<AuthorizeRequest>(y =>
                    y.ResponseMode == authorizeRequestDto.ResponseMode &&
                    y.CodeChallenge == authorizeRequestDto.CodeChallenge &&
                    y.Scope == authorizeRequestDto.Scope &&
                    y.AcrValues == authorizeRequestDto.AcrValues &&
                    y.ClientId == authorizeRequestDto.ClientId &&
                    y.Nonce == authorizeRequestDto.Nonce &&
                    y.RedirectUri == authorizeRequestDto.RedirectUri &&
                    y.CodeChallengeMethod == authorizeRequestDto.CodeChallengeMethod &&
                    y.State == authorizeRequestDto.State &&
                    y.ResponseType == authorizeRequestDto.ResponseType &&
                    y.DPoPJkt == authorizeRequestDto.DPoPJkt &&
                    y.Resource == authorizeRequestDto.Resource &&
                    y.RequestUri == null), CancellationToken.None))
            .ReturnsAsync(InteractionResult.Success(subjectIdentifier, authorizationGrantId))
            .Verifiable();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            RequestUri = givenRequestUri
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        secureRequestService.Verify();
        authorizeInteractionService.Verify();

        Assert.Equal(authorizationGrantId, processResult.Value!.AuthorizationGrantId);
        Assert.Equal(authorizeRequestDto.ResponseMode, processResult.Value!.ResponseMode);
        Assert.Equal(authorizeRequestDto.CodeChallenge, processResult.Value!.CodeChallenge);
        Assert.Equal(authorizeRequestDto.CodeChallengeMethod, processResult.Value!.CodeChallengeMethod);
        Assert.Equal(authorizeRequestDto.Scope, processResult.Value!.Scope);
        Assert.Equal(authorizeRequestDto.AcrValues, processResult.Value!.AcrValues);
        Assert.Equal(authorizeRequestDto.ClientId, processResult.Value!.ClientId);
        Assert.Equal(authorizeRequestDto.Nonce, processResult.Value!.Nonce);
        Assert.Equal(authorizeRequestDto.RedirectUri, processResult.Value!.RedirectUri);
        Assert.Equal(authorizeRequestDto.ResponseType, processResult.Value!.ResponseType);
        Assert.Equal(authorizeRequestDto.DPoPJkt, processResult.Value!.DPoPJkt);
        Assert.Equal(authorizeRequestDto.Resource, processResult.Value!.Resource);
        Assert.Null(processResult.Value!.RequestUri);
    }

    [Fact]
    public async Task Validate_ValidRequestObjectFromRequest_ExpectAuthorizeValidatedRequest()
    {
        // Arrange
        var secureRequestService = new Mock<ISecureRequestService>();
        var authorizeInteractionService = new Mock<IAuthorizeInteractionService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(secureRequestService);
            services.AddScopedMock(authorizeInteractionService);
        });
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>>();

        var client = await GetClient();
        var resource = await GetResource();

        const string givenRequestObject = "request_object";
        const string subjectIdentifier = "subjectIdentifier";
        const string authorizationGrantId = "authorizationGrantId";

        var authorizeRequestDto = new AuthorizeRequestDto
        {
            ResponseMode = ResponseModeConstants.FormPost,
            CodeChallenge = ProofKeyGenerator.GetProofKeyForCodeExchange().CodeChallenge,
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            ResponseType = ResponseTypeConstants.Code,
            Scope = [ScopeConstants.OpenId],
            AcrValues = [LevelOfAssuranceLow],
            ClientId = client.Id,
            Nonce = CryptographyHelper.GetRandomString(16),
            State = CryptographyHelper.GetRandomString(16),
            RedirectUri = client.RedirectUris.Single().Uri,
            DPoPJkt = CryptographyHelper.GetRandomString(16),
            Resource = [resource.ClientUri!]
        };

        secureRequestService
            .Setup(x =>
                x.GetRequestByObject(
                    givenRequestObject,
                    client.Id,
                    ClientTokenAudience.AuthorizationEndpoint,
                    CancellationToken.None)
                )
            .ReturnsAsync(authorizeRequestDto)
            .Verifiable();

        authorizeInteractionService
            .Setup(x =>
                x.GetInteractionResult(It.Is<AuthorizeRequest>(y =>
                    y.ResponseMode == authorizeRequestDto.ResponseMode &&
                    y.CodeChallenge == authorizeRequestDto.CodeChallenge &&
                    y.Scope == authorizeRequestDto.Scope &&
                    y.AcrValues == authorizeRequestDto.AcrValues &&
                    y.ClientId == authorizeRequestDto.ClientId &&
                    y.Nonce == authorizeRequestDto.Nonce &&
                    y.RedirectUri == authorizeRequestDto.RedirectUri &&
                    y.CodeChallengeMethod == authorizeRequestDto.CodeChallengeMethod &&
                    y.State == authorizeRequestDto.State &&
                    y.ResponseType == authorizeRequestDto.ResponseType &&
                    y.DPoPJkt == authorizeRequestDto.DPoPJkt &&
                    y.Resource == authorizeRequestDto.Resource &&
                    y.RequestUri == null), CancellationToken.None))
            .ReturnsAsync(InteractionResult.Success(subjectIdentifier, authorizationGrantId))
            .Verifiable();

        var request = new AuthorizeRequest
        {
            ClientId = client.Id,
            RequestObject = givenRequestObject
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        secureRequestService.Verify();
        authorizeInteractionService.Verify();

        Assert.Equal(authorizationGrantId, processResult.Value!.AuthorizationGrantId);
        Assert.Equal(authorizeRequestDto.ResponseMode, processResult.Value!.ResponseMode);
        Assert.Equal(authorizeRequestDto.CodeChallenge, processResult.Value!.CodeChallenge);
        Assert.Equal(authorizeRequestDto.CodeChallengeMethod, processResult.Value!.CodeChallengeMethod);
        Assert.Equal(authorizeRequestDto.Scope, processResult.Value!.Scope);
        Assert.Equal(authorizeRequestDto.AcrValues, processResult.Value!.AcrValues);
        Assert.Equal(authorizeRequestDto.ClientId, processResult.Value!.ClientId);
        Assert.Equal(authorizeRequestDto.Nonce, processResult.Value!.Nonce);
        Assert.Equal(authorizeRequestDto.RedirectUri, processResult.Value!.RedirectUri);
        Assert.Equal(authorizeRequestDto.ResponseType, processResult.Value!.ResponseType);
        Assert.Equal(authorizeRequestDto.DPoPJkt, processResult.Value!.DPoPJkt);
        Assert.Equal(authorizeRequestDto.Resource, processResult.Value!.Resource);
        Assert.Null(processResult.Value!.RequestUri);
    }

    private async Task<Client> GetClient()
    {
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            RequestUriExpiration = 60
        };
        var redirectUri = new RedirectUri("https://webapp.authserver.dk/callback", client);
        
        var openIdScope = await GetScope(ScopeConstants.OpenId);
        client.Scopes.Add(openIdScope);
        
        var grantType = await GetGrantType(GrantTypeConstants.AuthorizationCode);
        client.GrantTypes.Add(grantType);

        var codeResponseType = await GetResponseType(ResponseTypeConstants.Code);
        client.ResponseTypes.Add(codeResponseType);

        var noneResponseType = await GetResponseType(ResponseTypeConstants.None);
        client.ResponseTypes.Add(noneResponseType);

        await AddEntity(redirectUri);

        return client;
    }

    private async Task<Client> GetResource()
    {
        var resource = new Client("weather-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            ClientUri = "https://weather.authserver.dk"
        };
        var openIdScope = await GetScope(ScopeConstants.OpenId);
        resource.Scopes.Add(openIdScope);
        await AddEntity(resource);

        return resource;
    }

    private async Task<Client> GetClientWithoutScope()
    {
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var redirectUri = new RedirectUri("https://webapp.authserver.dk/callback", client);
        
        var grantType = await GetGrantType(GrantTypeConstants.AuthorizationCode);
        client.GrantTypes.Add(grantType);
        
        var codeResponseType = await GetResponseType(ResponseTypeConstants.Code);
        client.ResponseTypes.Add(codeResponseType);

        await AddEntity(redirectUri);

        return client;
    }

    private async Task<Client> GetClientWithoutGrantType()
    {
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var redirectUri = new RedirectUri("https://webapp.authserver.dk/callback", client);
        
        var openIdScope = await GetScope(ScopeConstants.OpenId);
        client.Scopes.Add(openIdScope);

        var codeResponseType = await GetResponseType(ResponseTypeConstants.Code);
        client.ResponseTypes.Add(codeResponseType);

        await AddEntity(redirectUri);

        return client;
    }

    private async Task<Client> GetClientWithoutRedirectUri()
    {
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        
        var openIdScope = await GetScope(ScopeConstants.OpenId);
        client.Scopes.Add(openIdScope);
        
        var grantType = await GetGrantType(GrantTypeConstants.AuthorizationCode);
        client.GrantTypes.Add(grantType);

        var codeResponseType = await GetResponseType(ResponseTypeConstants.Code);
        client.ResponseTypes.Add(codeResponseType);

        await AddEntity(client);

        return client;
    }
}