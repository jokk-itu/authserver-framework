using AuthServer.Authentication.Models;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Codes;
using AuthServer.Codes.Abstractions;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Helpers;
using AuthServer.Tests.Core;
using AuthServer.TokenByGrant;
using AuthServer.TokenByGrant.TokenDeviceCodeGrant;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.TokenByGrant.TokenDeviceCodeGrant;
public class DeviceCodeRequestValidatorTest : BaseUnitTest
{
    public DeviceCodeRequestValidatorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task Validate_EmptyGrantType_ExpectUnsupportedGrantType()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        var request = new TokenRequest();

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.UnsupportedGrantType, processResult);
    }

    [Fact]
    public async Task Validate_EmptyResource_ExpectInvalidResource()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidResource, processResult);
    }

    [Fact]
    public async Task Validate_NullDeviceCode_ExpectInvalidCode()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode,
            Resource = ["resource"]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidDeviceCode, processResult);
    }

    [Fact]
    public async Task Validate_NullCodeVerifier_ExpectInvalidCodeVerifier()
    {
        // Arrange
        var deviceCodeEncoder = new Mock<ICodeEncoder<EncodedDeviceCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(deviceCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        deviceCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedDeviceCode
            {
                UserCodeId = string.Empty,
                DeviceCodeId = string.Empty,
                AuthorizationGrantId = string.Empty,
                CodeChallenge = string.Empty,
                CodeChallengeMethod = string.Empty,
                Scope = [],
                Resource = []
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode,
            Resource = ["resource"]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidCodeVerifier, processResult);
        deviceCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_NoClientAuthentication_ExpectMultipleOrNoneClientMethod()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var deviceCodeEncoder = new Mock<ICodeEncoder<EncodedDeviceCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(deviceCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        deviceCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedDeviceCode
            {
                UserCodeId = string.Empty,
                DeviceCodeId = string.Empty,
                AuthorizationGrantId = string.Empty,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [],
                Resource = []
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode,
            Resource = ["resource"],
            CodeVerifier = proofKey.CodeVerifier
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.MultipleOrNoneClientMethod, processResult);
        deviceCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_InvalidClientAuthentication_ExpectInvalidClient()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var deviceCodeEncoder = new Mock<ICodeEncoder<EncodedDeviceCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(deviceCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        deviceCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedDeviceCode
            {
                UserCodeId = string.Empty,
                DeviceCodeId = string.Empty,
                AuthorizationGrantId = string.Empty,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [],
                Resource = []
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode,
            Resource = ["resource"],
            CodeVerifier = proofKey.CodeVerifier,
            ClientAuthentications =
            [
                new ClientIdAuthentication("clientId")
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidClient, processResult);
        deviceCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_InvalidDeviceCodeId_ExpectInvalidDeviceCode()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var deviceCodeEncoder = new Mock<ICodeEncoder<EncodedDeviceCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(deviceCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        await SaveChangesAsync();

        deviceCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedDeviceCode
            {
                UserCodeId = string.Empty,
                DeviceCodeId = "invalid_device_code_id",
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [],
                Resource = []
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode,
            Resource = ["resource"],
            CodeVerifier = proofKey.CodeVerifier,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    authorizationGrant.Client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidDeviceCode, processResult);
        deviceCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_ExpiredDeviceCode_ExpectDeviceCodeExpired()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var deviceCodeEncoder = new Mock<ICodeEncoder<EncodedDeviceCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(deviceCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        var deviceCodeId = authorizationGrant.DeviceCodes.Single().Id;
        typeof(Code)
            .GetProperty(nameof(Code.ExpiresAt))!
            .SetValue(authorizationGrant.DeviceCodes.Single(), DateTime.UtcNow.AddSeconds(-30));

        await SaveChangesAsync();

        deviceCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedDeviceCode
            {
                UserCodeId = string.Empty,
                DeviceCodeId = deviceCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [],
                Resource = []
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode,
            Resource = ["resource"],
            CodeVerifier = proofKey.CodeVerifier,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    authorizationGrant.Client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.DeviceCodeExpired, processResult);
        deviceCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_NotWithinInterval_ExpectDeviceSlowDown()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var deviceCodeEncoder = new Mock<ICodeEncoder<EncodedDeviceCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(deviceCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        var deviceCodeId = authorizationGrant.DeviceCodes.Single().Id;
        authorizationGrant.DeviceCodes.Single().UpdatePoll();
        await SaveChangesAsync();

        deviceCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedDeviceCode
            {
                UserCodeId = string.Empty,
                DeviceCodeId = deviceCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [],
                Resource = []
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode,
            Resource = ["resource"],
            CodeVerifier = proofKey.CodeVerifier,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    authorizationGrant.Client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.DeviceSlowDown(deviceCodeId), processResult);
        deviceCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_RevokedDeviceCode_ExpectDeviceAuthorizationDenied()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var deviceCodeEncoder = new Mock<ICodeEncoder<EncodedDeviceCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(deviceCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        var deviceCodeId = authorizationGrant.DeviceCodes.Single().Id;
        authorizationGrant.DeviceCodes.Single().Revoke();
        await SaveChangesAsync();

        deviceCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedDeviceCode
            {
                UserCodeId = string.Empty,
                DeviceCodeId = deviceCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [],
                Resource = []
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode,
            Resource = ["resource"],
            CodeVerifier = proofKey.CodeVerifier,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    authorizationGrant.Client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.DeviceAuthorizationDenied, processResult);
        deviceCodeEncoder.Verify();
    }

    [Theory]
    [InlineData(null)]
    [InlineData(-5)]
    public async Task Validate_DeviceCodeDoesNotHaveGrant_ExpectDeviceAuthorizationPending(int? latestPoll)
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var deviceCodeEncoder = new Mock<ICodeEncoder<EncodedDeviceCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(deviceCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        var deviceCodeId = authorizationGrant.DeviceCodes.Single().Id;
        
        typeof(DeviceCode)
            .GetProperty(nameof(DeviceCode.LatestPoll))!
            .SetValue(authorizationGrant.DeviceCodes.Single(),
                latestPoll is null ? null : DateTime.UtcNow.AddSeconds(latestPoll.Value));

        authorizationGrant.DeviceCodes.Clear();
        await SaveChangesAsync();

        deviceCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedDeviceCode
            {
                UserCodeId = string.Empty,
                DeviceCodeId = deviceCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [],
                Resource = []
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode,
            Resource = ["resource"],
            CodeVerifier = proofKey.CodeVerifier,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    authorizationGrant.Client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.DeviceAuthorizationPending(deviceCodeId), processResult);
        deviceCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_RevokedGrant_ExpectInvalidGrant()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var deviceCodeEncoder = new Mock<ICodeEncoder<EncodedDeviceCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(deviceCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        var deviceCodeId = authorizationGrant.DeviceCodes.Single().Id;
        authorizationGrant.Revoke();
        await SaveChangesAsync();

        deviceCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedDeviceCode
            {
                UserCodeId = string.Empty,
                DeviceCodeId = deviceCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [],
                Resource = []
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode,
            Resource = ["resource"],
            CodeVerifier = proofKey.CodeVerifier,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    authorizationGrant.Client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidGrant, processResult);
        deviceCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_UnauthorizedForDeviceCode_ExpectUnauthorizedForGrantType()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var deviceCodeEncoder = new Mock<ICodeEncoder<EncodedDeviceCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(deviceCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        authorizationGrant.Client.GrantTypes.Clear();
        var deviceCodeId = authorizationGrant.DeviceCodes.Single().Id;
        await SaveChangesAsync();

        deviceCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedDeviceCode
            {
                UserCodeId = string.Empty,
                DeviceCodeId = deviceCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [],
                Resource = []
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode,
            Resource = ["resource"],
            CodeVerifier = proofKey.CodeVerifier,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    authorizationGrant.Client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.UnauthorizedForGrantType, processResult);
        deviceCodeEncoder.Verify();
    }

    [Theory]
    [InlineData(true, null)]
    [InlineData(false, "jkt")]
    [InlineData(true, "jkt")]
    public async Task Validate_RequireDPoPWithoutDPoPProof_ExpectDPoPRequired(bool requireDPoP, string? dPoPJkt)
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var deviceCodeEncoder = new Mock<ICodeEncoder<EncodedDeviceCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(deviceCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        authorizationGrant.Client.RequireDPoPBoundAccessTokens = requireDPoP;
        var deviceCodeId = authorizationGrant.DeviceCodes.Single().Id;

        deviceCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedDeviceCode
            {
                UserCodeId = string.Empty,
                DeviceCodeId = deviceCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                DPoPJkt = dPoPJkt,
                Scope = [],
                Resource = []
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode,
            Resource = ["resource"],
            CodeVerifier = proofKey.CodeVerifier,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    authorizationGrant.Client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.DPoPRequired, processResult);
        deviceCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_InvalidDPoP_ExpectInvalidDPoP()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var deviceCodeEncoder = new Mock<ICodeEncoder<EncodedDeviceCode>>();
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(deviceCodeEncoder);
            services.AddScopedMock(dPoPService);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        var deviceCodeId = authorizationGrant.DeviceCodes.Single().Id;

        deviceCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedDeviceCode
            {
                UserCodeId = string.Empty,
                DeviceCodeId = deviceCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [],
                Resource = []
            })
            .Verifiable();

        const string dPoPProof = "invalid_dpop_proof";
        dPoPService
            .Setup(x => x.ValidateDPoP(dPoPProof, authorizationGrant.Client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = false
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode,
            Resource = ["resource"],
            CodeVerifier = proofKey.CodeVerifier,
            DPoP = dPoPProof,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    authorizationGrant.Client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidDPoP, processResult);
        deviceCodeEncoder.Verify();
        dPoPService.Verify();
    }

    [Fact]
    public async Task Validate_MissingNonce_ExpectRenewDPoPNonce()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var deviceCodeEncoder = new Mock<ICodeEncoder<EncodedDeviceCode>>();
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(deviceCodeEncoder);
            services.AddScopedMock(dPoPService);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        var deviceCodeId = authorizationGrant.DeviceCodes.Single().Id;

        deviceCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedDeviceCode
            {
                UserCodeId = string.Empty,
                DeviceCodeId = deviceCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [],
                Resource = []
            })
            .Verifiable();

        const string dPoPProof = "dpop_proof_without_nonce";
        dPoPService
            .Setup(x => x.ValidateDPoP(dPoPProof, authorizationGrant.Client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult { IsValid = false, RenewDPoPNonce = true })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode,
            Resource = ["resource"],
            CodeVerifier = proofKey.CodeVerifier,
            DPoP = dPoPProof,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    authorizationGrant.Client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.RenewDPoPNonce(authorizationGrant.Client.Id), processResult);
        deviceCodeEncoder.Verify();
        dPoPService.Verify();
    }

    [Fact]
    public async Task Validate_DPoPUnequalToDPoPJkt_ExpectInvalidDPoPJktMatch()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var deviceCodeEncoder = new Mock<ICodeEncoder<EncodedDeviceCode>>();
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(deviceCodeEncoder);
            services.AddScopedMock(dPoPService);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        var deviceCodeId = authorizationGrant.DeviceCodes.Single().Id;

        deviceCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedDeviceCode
            {
                UserCodeId = string.Empty,
                DeviceCodeId = deviceCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                DPoPJkt = "jkt",
                Scope = [],
                Resource = []
            })
            .Verifiable();

        const string dPoPProof = "dpop_proof_unequal_to_dpop_jkt";
        dPoPService
            .Setup(x => x.ValidateDPoP(dPoPProof, authorizationGrant.Client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = true,
                DPoPJkt = "unequal_jkt"
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode,
            Resource = ["resource"],
            CodeVerifier = proofKey.CodeVerifier,
            DPoP = dPoPProof,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    authorizationGrant.Client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidDPoPJktMatch, processResult);
        deviceCodeEncoder.Verify();
        dPoPService.Verify();
    }

    [Fact]
    public async Task Validate_NoConsentedScope_ExpectConsentRequired()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var deviceCodeEncoder = new Mock<ICodeEncoder<EncodedDeviceCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(deviceCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        authorizationGrant.AuthorizationGrantConsents.Clear();
        var deviceCodeId = authorizationGrant.DeviceCodes.Single().Id;
        await SaveChangesAsync();

        deviceCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedDeviceCode
            {
                UserCodeId = string.Empty,
                DeviceCodeId = deviceCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [ScopeConstants.OpenId],
                Resource = []
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode,
            Resource = ["resource"],
            CodeVerifier = proofKey.CodeVerifier,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    authorizationGrant.Client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.ConsentRequired, processResult);
        deviceCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_UnauthorizedScopeForClient_ExpectUnauthorizedForScope()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var deviceCodeEncoder = new Mock<ICodeEncoder<EncodedDeviceCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(deviceCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        authorizationGrant.Client.Scopes.Remove(await GetScope(ScopeConstants.OpenId));
        var deviceCodeId = authorizationGrant.DeviceCodes.Single().Id;
        await SaveChangesAsync();

        deviceCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedDeviceCode
            {
                UserCodeId = string.Empty,
                DeviceCodeId = deviceCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [ScopeConstants.OpenId],
                Resource = []
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode,
            Resource = ["https://weather.authserver.dk"],
            CodeVerifier = proofKey.CodeVerifier,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    authorizationGrant.Client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.UnauthorizedForScope, processResult);
        deviceCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_ExceedConsentedScope_ExpectScopeExceedsConsentedScope()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var deviceCodeEncoder = new Mock<ICodeEncoder<EncodedDeviceCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(deviceCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        var weatherClient = await GetWeatherClient();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        var deviceCodeId = authorizationGrant.DeviceCodes.Single().Id;

        deviceCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedDeviceCode
            {
                UserCodeId = string.Empty,
                DeviceCodeId = deviceCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [ScopeConstants.OpenId, ScopeConstants.Profile],
                Resource = []
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode,
            Resource = [weatherClient.ClientUri!],
            CodeVerifier = proofKey.CodeVerifier,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    authorizationGrant.Client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.ScopeExceedsConsentedScope, processResult);
        deviceCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_ExceedConsentedScopeWithResource_ExpectScopeExceedsConsentedScope()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizationCodeEncoder = new Mock<ICodeEncoder<EncodedDeviceCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        var deviceCodeId = authorizationGrant.DeviceCodes.Single().Id;

        authorizationCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedDeviceCode
            {
                UserCodeId = string.Empty,
                DeviceCodeId = deviceCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [ScopeConstants.OpenId],
                Resource = []
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode,
            Resource = ["other_resource"],
            CodeVerifier = proofKey.CodeVerifier,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    authorizationGrant.Client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.ScopeExceedsConsentedScope, processResult);
        authorizationCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_ResourceDoesNotExist_ExpectInvalidResource()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var deviceCodeEncoder = new Mock<ICodeEncoder<EncodedDeviceCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(deviceCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        authorizationGrant.Client.RequireConsent = false;
        authorizationGrant.AuthorizationGrantConsents.Clear();
        var deviceCodeId = authorizationGrant.DeviceCodes.Single().Id;
        await SaveChangesAsync();

        deviceCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedDeviceCode
            {
                UserCodeId = string.Empty,
                DeviceCodeId = deviceCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [ScopeConstants.OpenId],
                Resource = []
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode,
            Resource = ["resource"],
            CodeVerifier = proofKey.CodeVerifier,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    authorizationGrant.Client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidResource, processResult);
        deviceCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_ValidatedRequest_ExpectValidatedRequest()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var deviceCodeEncoder = new Mock<ICodeEncoder<EncodedDeviceCode>>();
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(deviceCodeEncoder);
            services.AddScopedMock(dPoPService);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        var deviceCodeId = authorizationGrant.DeviceCodes.Single().Id;
        var weatherClient = await GetWeatherClient();

        const string dPoPJkt = "jkt";
        const string dPoP = "dpop";

        deviceCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedDeviceCode
            {
                UserCodeId = string.Empty,
                DeviceCodeId = deviceCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                DPoPJkt = "jkt",
                Scope = [ScopeConstants.OpenId],
                Resource = []
            })
            .Verifiable();

        dPoPService
            .Setup(x => x.ValidateDPoP(dPoP, authorizationGrant.Client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = true,
                DPoPJkt = dPoPJkt
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.DeviceCode,
            Resource = [weatherClient.ClientUri!],
            CodeVerifier = proofKey.CodeVerifier,
            DPoP = dPoP,
            ClientAuthentications =
            [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    authorizationGrant.Client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.True(processResult.IsSuccess);
        Assert.Equal(authorizationGrant.Client.Id, processResult.Value!.ClientId);
        Assert.Equal(authorizationGrant.Id, processResult.Value!.AuthorizationGrantId);
        Assert.Equal(deviceCodeId, processResult.Value!.DeviceCodeId);
        Assert.Equal(request.Resource, processResult.Value!.Resource);
        Assert.Equal([ScopeConstants.OpenId], processResult.Value!.Scope);
        Assert.Equal(dPoPJkt, processResult.Value!.DPoPJkt);
        deviceCodeEncoder.Verify();
        dPoPService.Verify();
    }

    private async Task<DeviceCodeGrant> GetAuthorizationGrant(string plainSecret)
    {
        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);

        var client = new Client("webapp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            DeviceCodeExpiration = 300
        };
        var hashedSecret = CryptographyHelper.HashPassword(plainSecret);
        client.SetSecret(hashedSecret);

        var openIdScope = await GetScope(ScopeConstants.OpenId);
        var profileScope = await GetScope(ScopeConstants.Profile);
        client.Scopes.Add(openIdScope);
        client.Scopes.Add(profileScope);

        var deviceCodeGrantType = await GetGrantType(GrantTypeConstants.DeviceCode);
        client.GrantTypes.Add(deviceCodeGrantType);

        var authenticationContextReference = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new DeviceCodeGrant(session, client, subjectIdentifier.Id, authenticationContextReference);
        var deviceCode = new DeviceCode(client.DeviceCodeExpiration!.Value, 5);
        deviceCode.SetRawValue("device_code");

        authorizationGrant.DeviceCodes.Add(deviceCode);

        var scopeConsent = new ScopeConsent(subjectIdentifier, client, openIdScope);
        var authorizationGrantScopeConsent = new AuthorizationGrantScopeConsent(
            scopeConsent, authorizationGrant, "https://weather.authserver.dk");

        await AddEntity(authorizationGrantScopeConsent);

        return authorizationGrant;
    }

    private async Task<Client> GetWeatherClient()
    {
        var weatherClient = new Client("weather-api", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            ClientUri = "https://weather.authserver.dk"
        };
        var openIdScope = await GetScope(ScopeConstants.OpenId);
        weatherClient.Scopes.Add(openIdScope);
        await AddEntity(weatherClient);
        return weatherClient;
    }
}