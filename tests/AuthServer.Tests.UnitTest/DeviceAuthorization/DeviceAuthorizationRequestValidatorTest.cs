using AuthServer.Authentication.Models;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.DeviceAuthorization;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Helpers;
using AuthServer.Tests.Core;
using AuthServer.TokenDecoders;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.DeviceAuthorization;

public class DeviceAuthorizationRequestValidatorTest : BaseUnitTest
{
    public DeviceAuthorizationRequestValidatorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task Validate_NoClientAuthentication_ExpectMultipleOrNoneClientMethod()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        var request = new DeviceAuthorizationRequest();

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.False(processResult.IsSuccess);
        Assert.Equal(DeviceAuthorizationError.MultipleOrNoneClientMethod, processResult.Error);
    }

    [Fact]
    public async Task Validate_InvalidClientAuthentication_ExpectInvalidClient()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        var request = new DeviceAuthorizationRequest
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
        Assert.Equal(DeviceAuthorizationError.InvalidClient, processResult.Error);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(true, true)]
    public async Task Validate_RequireSignedRequestWithEmptyRequestAndRequestUri_ExpectRequestRequiredAsRequestObject(bool clientRequires, bool serverRequires)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        DiscoveryDocument.RequireSignedRequestObject = serverRequires;
        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        client.RequireSignedRequestObject = clientRequires;
        await SaveChangesAsync();

        var request = new DeviceAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.False(processResult.IsSuccess);
        Assert.Equal(DeviceAuthorizationError.RequestRequiredAsRequestObject, processResult);
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
            IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var request = new DeviceAuthorizationRequest
        {
            RequestObject = "invalid_request",
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.False(processResult.IsSuccess);
        Assert.Equal(DeviceAuthorizationError.InvalidRequest, processResult);
    }

    [Fact]
    public async Task Validate_UnauthorizedGrantType_ExpectUnauthorizedForGrant()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        client.GrantTypes.Clear();
        await SaveChangesAsync();

        var request = new DeviceAuthorizationRequest
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
        Assert.Equal(DeviceAuthorizationError.UnauthorizedForGrant, processResult.Error);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task Validate_InvalidNonce_ExpectInvalidNonce(string? nonce)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var request = new DeviceAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            Nonce = nonce
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(DeviceAuthorizationError.InvalidNonce, processResult.Error);
    }

    [Fact]
    public async Task Validate_DuplicateNonce_ExpectReplayNonce()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var authenticationContextReference = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, authenticationContextReference);
        var nonceValue = Guid.NewGuid().ToString();
        var nonce = new AuthorizationGrantNonce(nonceValue, nonceValue.Sha256(), authorizationGrant);
        await AddEntity(nonce);

        var request = new DeviceAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            Nonce = nonceValue
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(DeviceAuthorizationError.ReplayNonce, processResult.Error);
    }

    [Fact]
    public async Task Validate_InvalidCodeChallengeMethod_ExpectInvalidCodeChallengeMethod()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var request = new DeviceAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = "invalid_code_challenge_method"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(DeviceAuthorizationError.InvalidCodeChallengeMethod, processResult.Error);
    }

    [Fact]
    public async Task Validate_InvalidCodeChallenge_ExpectInvalidCodeChallenge()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var request = new DeviceAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = "invalid_code_challenge"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(DeviceAuthorizationError.InvalidCodeChallenge, processResult.Error);
    }

    [Fact]
    public async Task Validate_InvalidScope_ExpectInvalidScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();

        var request = new DeviceAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = proofKey.CodeChallengeMethod,
            CodeChallenge = proofKey.CodeChallenge
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(DeviceAuthorizationError.InvalidOpenIdScope, processResult.Error);
    }

    [Fact]
    public async Task Validate_UnauthorizedScope_ExpectUnauthorizedScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        client.Scopes.Clear();
        await SaveChangesAsync();
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();

        var request = new DeviceAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = proofKey.CodeChallengeMethod,
            CodeChallenge = proofKey.CodeChallenge,
            Scope = [ScopeConstants.OpenId]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(DeviceAuthorizationError.UnauthorizedScope, processResult.Error);
    }

    [Fact]
    public async Task Validate_EmptyResource_ExpectInvalidTarget()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();

        var request = new DeviceAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = proofKey.CodeChallengeMethod,
            CodeChallenge = proofKey.CodeChallenge,
            Scope = [ScopeConstants.OpenId]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(DeviceAuthorizationError.InvalidResource, processResult.Error);
    }

    [Fact]
    public async Task Validate_InvalidResource_ExpectInvalidTarget()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();

        var request = new DeviceAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = proofKey.CodeChallengeMethod,
            CodeChallenge = proofKey.CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = ["invalid_resource"]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(DeviceAuthorizationError.InvalidResource, processResult.Error);
    }

    [Fact]
    public async Task Validate_InvalidAcrValues_ExpectInvalidAcrValues()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();

        var resource = await GetResource();

        var request = new DeviceAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = proofKey.CodeChallengeMethod,
            CodeChallenge = proofKey.CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!],
            AcrValues = ["invalid_acr_value"]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(DeviceAuthorizationError.InvalidAcrValues, processResult.Error);
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
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        DiscoveryDocument.GrantManagementActionRequired = true;

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();

        var resource = await GetResource();

        var request = new DeviceAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = proofKey.CodeChallengeMethod,
            CodeChallenge = proofKey.CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!],
            GrantManagementAction = grantManagementAction,
            GrantId = grantId
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(DeviceAuthorizationError.InvalidGrantManagement, processResult.Error);
    }

    [Fact]
    public async Task Validate_InvalidGrantId_ExpectInvalidGrantId()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();

        var resource = await GetResource();

        var request = new DeviceAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = proofKey.CodeChallengeMethod,
            CodeChallenge = proofKey.CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!],
            GrantManagementAction = GrantManagementActionConstants.Replace,
            GrantId = "invalid_grant_id"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(DeviceAuthorizationError.InvalidGrantId, processResult.Error);
    }

    [Fact]
    public async Task Validate_MissingDPoPAndClientRequiresDPoP_ExpectDPoPRequired()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        client.RequireDPoPBoundAccessTokens = true;
        await SaveChangesAsync();

        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();

        var resource = await GetResource();

        var request = new DeviceAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = proofKey.CodeChallengeMethod,
            CodeChallenge = proofKey.CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        Assert.False(processResult.IsSuccess);
        Assert.Equal(DeviceAuthorizationError.DPoPRequired, processResult.Error);
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
            .GetRequiredService<IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();

        const string dPoP = "invalid_dpop";
        dPoPService
            .Setup(x => x.ValidateDPoP(dPoP, client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult { IsValid = false })
            .Verifiable();

        var resource = await GetResource();

        var request = new DeviceAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = proofKey.CodeChallengeMethod,
            CodeChallenge = proofKey.CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!],
            DPoP = dPoP
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        dPoPService.Verify();
        Assert.False(processResult.IsSuccess);
        Assert.Equal(DeviceAuthorizationError.InvalidDPoP, processResult.Error);
    }

    [Fact]
    public async Task Validate_MissingNonce_ExpectRenewDPoPNonce()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();

        const string dPoP = "dpop";
        dPoPService
            .Setup(x => x.ValidateDPoP(dPoP, client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult { IsValid = false, RenewDPoPNonce = true })
            .Verifiable();

        var resource = await GetResource();

        var request = new DeviceAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            Nonce = Guid.NewGuid().ToString(),
            CodeChallengeMethod = proofKey.CodeChallengeMethod,
            CodeChallenge = proofKey.CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!],
            DPoP = dPoP
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        dPoPService.Verify();
        Assert.False(processResult.IsSuccess);
        Assert.Equal(DeviceAuthorizationError.RenewDPoPNonce(client.Id), processResult.Error);
    }
    
    [Fact]
    public async Task Validate_MinimalValidRequest_ExpectDeviceAuthorizationValidatedRequest()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        var resource = await GetResource();

        var request = new DeviceAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            Nonce = CryptographyHelper.GetRandomString(16),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = ProofKeyGenerator.GetProofKeyForCodeExchange().CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            Resource = [resource.ClientUri!]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.True(processResult.IsSuccess);
        Assert.Equal(request.CodeChallenge, processResult.Value!.CodeChallenge);
        Assert.Equal(request.CodeChallengeMethod, processResult.Value!.CodeChallengeMethod);
        Assert.Equal(request.Scope, processResult.Value!.Scope);
        Assert.Equal(request.Resource, processResult.Value!.Resource);
        Assert.Equal(request.Nonce, processResult.Value!.Nonce);
    }

    [Fact]
    public async Task Validate_FullValidatedRequest_ExpectDeviceAuthorizationValidatedRequest()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        var resource = await GetResource();
        
        const string dPoP = "dpop";
        const string dPoPJkt = "dpop_jkt";
        dPoPService
            .Setup(x => x.ValidateDPoP(dPoP, client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult { IsValid = true, DPoPJkt = dPoPJkt })
            .Verifiable();

        var request = new DeviceAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            Nonce = CryptographyHelper.GetRandomString(16),
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            CodeChallenge = ProofKeyGenerator.GetProofKeyForCodeExchange().CodeChallenge,
            Scope = [ScopeConstants.OpenId],
            AcrValues = [LevelOfAssuranceSubstantial],
            Resource = [resource.ClientUri!],
            DPoP = dPoP,
            GrantManagementAction = GrantManagementActionConstants.Create
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        dPoPService.Verify();
        
        Assert.True(processResult.IsSuccess);
        Assert.Equal(request.CodeChallenge, processResult.Value!.CodeChallenge);
        Assert.Equal(request.CodeChallengeMethod, processResult.Value!.CodeChallengeMethod);
        Assert.Equal(request.Scope, processResult.Value!.Scope);
        Assert.Equal(request.AcrValues, processResult.Value!.AcrValues);
        Assert.Equal(request.Resource, processResult.Value!.Resource);
        Assert.Equal(request.Nonce, processResult.Value!.Nonce);
        Assert.Equal(dPoPJkt,  processResult.Value!.DPoPJkt);
        Assert.Null(processResult.Value!.AuthorizationGrantId);
        Assert.Equal(request.GrantManagementAction, processResult.Value!.GrantManagementAction);
    }

    [Fact]
    public async Task Validate_ValidRequestObjectFromRequest_ExpectDeviceAuthorizationValidatedRequest()
    {
        // Arrange
        var secureRequestService = new Mock<ISecureRequestService>();
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(secureRequestService);
            services.AddScopedMock(dPoPService);
        });
        var validator = serviceProvider.GetRequiredService<
            IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var grant = new DeviceCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);
        await AddEntity(grant);

        var resource = await GetResource();
        
        const string dPoP = "dpop";
        const string dPoPJkt = "dpop_jkt";
        dPoPService
            .Setup(x => x.ValidateDPoP(dPoP, client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult { IsValid = true, DPoPJkt = dPoPJkt })
            .Verifiable();

        const string givenRequestObject = "request_object";

        var authorizeRequestDto = new AuthorizeRequestDto
        {
            CodeChallenge = ProofKeyGenerator.GetProofKeyForCodeExchange().CodeChallenge,
            CodeChallengeMethod = CodeChallengeMethodConstants.S256,
            Scope = [ScopeConstants.OpenId],
            AcrValues = [LevelOfAssuranceLow],
            Nonce = CryptographyHelper.GetRandomString(16),
            Resource = [resource.ClientUri!],
            GrantId = grant.Id,
            GrantManagementAction = GrantManagementActionConstants.Merge
        };

        secureRequestService
            .Setup(x =>
                x.GetRequestByObject(
                    givenRequestObject,
                    client.Id,
                    ClientTokenAudience.DeviceAuthorizationEndpoint,
                    CancellationToken.None)
                )
            .ReturnsAsync(authorizeRequestDto)
            .Verifiable();

        var request = new DeviceAuthorizationRequest
        {
            ClientAuthentications =
            [
                new ClientSecretAuthentication(TokenEndpointAuthMethod.ClientSecretBasic, client.Id, plainSecret)
            ],
            DPoP = dPoP,
            RequestObject = givenRequestObject
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        secureRequestService.Verify();
        dPoPService.Verify();

        Assert.True(processResult.IsSuccess);
        Assert.Equal(authorizeRequestDto.CodeChallenge, processResult.Value!.CodeChallenge);
        Assert.Equal(authorizeRequestDto.CodeChallengeMethod, processResult.Value!.CodeChallengeMethod);
        Assert.Equal(authorizeRequestDto.Scope, processResult.Value!.Scope);
        Assert.Equal(authorizeRequestDto.AcrValues, processResult.Value!.AcrValues);
        Assert.Equal(client.Id, processResult.Value!.ClientId);
        Assert.Equal(dPoPJkt, processResult.Value!.DPoPJkt);
        Assert.Equal(authorizeRequestDto.Nonce, processResult.Value!.Nonce);
        Assert.Equal(authorizeRequestDto.Resource, processResult.Value!.Resource);
        Assert.Equal(authorizeRequestDto.GrantId, processResult.Value!.AuthorizationGrantId);
        Assert.Equal(authorizeRequestDto.GrantManagementAction, processResult.Value!.GrantManagementAction);
    }

    private async Task<Client> GetClient(string plainSecret)
    {
        var client = new Client("tv-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        client.GrantTypes.Add(await GetGrantType(GrantTypeConstants.DeviceCode));
        client.Scopes.Add(await GetScope(ScopeConstants.OpenId));
        var hashedSecret = CryptographyHelper.HashPassword(plainSecret);
        client.SetSecret(hashedSecret);
        await AddEntity(client);
        return client;
    }

    private async Task<Client> GetResource()
    {
        var resource = new Client("weather-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            ClientUri = "https://weather.authserver.dk"
        };
        resource.Scopes.Add(await GetScope(ScopeConstants.OpenId));
        await AddEntity(resource);

        return resource;
    }
}