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
using AuthServer.TokenByGrant.TokenAuthorizationCodeGrant;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;
using ProofKeyGenerator = AuthServer.Tests.Core.ProofKeyGenerator;

namespace AuthServer.Tests.UnitTest.TokenByGrant.TokenAuthorizationCodeGrant;

public class AuthorizationCodeRequestValidatorTest : BaseUnitTest
{
    public AuthorizationCodeRequestValidatorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task Validate_EmptyGrantType_ExpectUnsupportedGrantType()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

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
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.AuthorizationCode
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidResource, processResult);
    }

    [Fact]
    public async Task Validate_NullCode_ExpectInvalidCode()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.AuthorizationCode,
            Resource = ["resource"]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidCode, processResult);
    }

    [Fact]
    public async Task Validate_NullCodeVerifier_ExpectInvalidCodeVerifier()
    {
        // Arrange
        var authorizationCodeEncoder = new Mock<ICodeEncoder<EncodedAuthorizationCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

        authorizationCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedAuthorizationCode
            {
                AuthorizationCodeId = string.Empty,
                AuthorizationGrantId = string.Empty,
                CodeChallenge = string.Empty,
                CodeChallengeMethod = string.Empty,
                Scope = []
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.AuthorizationCode,
            Resource = ["resource"]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidCodeVerifier, processResult);
        authorizationCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_MismatchingRedirectUris_ExpectInvalidRedirectUri()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizationCodeEncoder = new Mock<ICodeEncoder<EncodedAuthorizationCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

        authorizationCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedAuthorizationCode
            {
                AuthorizationCodeId = string.Empty,
                AuthorizationGrantId = string.Empty,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [],
                RedirectUri = "valid_redirect_uri"
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.AuthorizationCode,
            Resource = ["resource"],
            RedirectUri = "invalid_redirect_uri",
            CodeVerifier = proofKey.CodeVerifier
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidRedirectUri, processResult);
        authorizationCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_NoClientAuthentication_ExpectMultipleOrNoneClientMethod()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizationCodeEncoder = new Mock<ICodeEncoder<EncodedAuthorizationCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

        authorizationCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedAuthorizationCode
            {
                AuthorizationCodeId = string.Empty,
                AuthorizationGrantId = string.Empty,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [],
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.AuthorizationCode,
            Resource = ["resource"],
            CodeVerifier = proofKey.CodeVerifier
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.MultipleOrNoneClientMethod, processResult);
        authorizationCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_InvalidClientAuthentication_ExpectInvalidClient()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizationCodeEncoder = new Mock<ICodeEncoder<EncodedAuthorizationCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

        authorizationCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedAuthorizationCode
            {
                AuthorizationCodeId = string.Empty,
                AuthorizationGrantId = string.Empty,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [],
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.AuthorizationCode,
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
        authorizationCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_RevokedGrant_ExpectInvalidGrant()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizationCodeEncoder = new Mock<ICodeEncoder<EncodedAuthorizationCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        authorizationGrant.Revoke();
        var authorizationCodeId = authorizationGrant.AuthorizationCodes.Single().Id;
        await SaveChangesAsync();

        authorizationCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedAuthorizationCode
            {
                AuthorizationCodeId = authorizationCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [],
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.AuthorizationCode,
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
        authorizationCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_RedeemedAuthorizationCode_ExpectInvalidGrant()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizationCodeEncoder = new Mock<ICodeEncoder<EncodedAuthorizationCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        var authorizationCode = authorizationGrant.AuthorizationCodes.Single();
        authorizationCode.Redeem();
        await SaveChangesAsync();

        authorizationCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedAuthorizationCode
            {
                AuthorizationCodeId = authorizationCode.Id,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [],
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.AuthorizationCode,
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
        authorizationCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_ExpiredAuthorizationCode_ExpectInvalidGrant()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizationCodeEncoder = new Mock<ICodeEncoder<EncodedAuthorizationCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        var authorizationCode = authorizationGrant.AuthorizationCodes.Single();
        typeof(Code)
            .GetProperty(nameof(Code.ExpiresAt))!
            .SetValue(authorizationCode, DateTime.UtcNow.AddSeconds(-60));

        await SaveChangesAsync();

        authorizationCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedAuthorizationCode
            {
                AuthorizationCodeId = authorizationCode.Id,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [],
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.AuthorizationCode,
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
        authorizationCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_UnauthorizedForAuthorizationCode_ExpectUnauthorizedForGrantType()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizationCodeEncoder = new Mock<ICodeEncoder<EncodedAuthorizationCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        authorizationGrant.Client.GrantTypes.Clear();
        var authorizationCodeId = authorizationGrant.AuthorizationCodes.Single().Id;
        await SaveChangesAsync();

        authorizationCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedAuthorizationCode
            {
                AuthorizationCodeId = authorizationCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [],
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.AuthorizationCode,
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
        authorizationCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_UnauthorizedRedirectUri_ExpectUnauthorizedForRedirectUri()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizationCodeEncoder = new Mock<ICodeEncoder<EncodedAuthorizationCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        var authorizationCodeId = authorizationGrant.AuthorizationCodes.Single().Id;

        authorizationCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedAuthorizationCode
            {
                AuthorizationCodeId = authorizationCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [],
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.AuthorizationCode,
            Resource = ["resource"],
            CodeVerifier = proofKey.CodeVerifier,
            RedirectUri = "https://client.authserver.dk/invalid-callback",
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
        Assert.Equal(TokenError.UnauthorizedForRedirectUri, processResult);
        authorizationCodeEncoder.Verify();
    }

    [Theory]
    [InlineData(true, null)]
    [InlineData(false, "jkt")]
    [InlineData(true, "jkt")]
    public async Task Validate_RequireDPoPWithoutDPoPProof_ExpectDPoPRequired(bool requireDPoP, string? dPoPJkt)
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizationCodeEncoder = new Mock<ICodeEncoder<EncodedAuthorizationCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        authorizationGrant.Client.RequireDPoPBoundAccessTokens = requireDPoP;
        var authorizationCodeId = authorizationGrant.AuthorizationCodes.Single().Id;

        authorizationCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedAuthorizationCode
            {
                AuthorizationCodeId = authorizationCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                DPoPJkt = dPoPJkt,
                Scope = [],
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.AuthorizationCode,
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
        authorizationCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_InvalidDPoP_ExpectInvalidDPoP()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizationCodeEncoder = new Mock<ICodeEncoder<EncodedAuthorizationCode>>();
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationCodeEncoder);
            services.AddScopedMock(dPoPService);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        var authorizationCodeId = authorizationGrant.AuthorizationCodes.Single().Id;

        authorizationCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedAuthorizationCode
            {
                AuthorizationCodeId = authorizationCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [],
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
            GrantType = GrantTypeConstants.AuthorizationCode,
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
        authorizationCodeEncoder.Verify();
        dPoPService.Verify();
    }

    [Fact]
    public async Task Validate_DPoPWithoutNonceClaim_ExpectUseDPoPNonce()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizationCodeEncoder = new Mock<ICodeEncoder<EncodedAuthorizationCode>>();
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationCodeEncoder);
            services.AddScopedMock(dPoPService);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        var authorizationCodeId = authorizationGrant.AuthorizationCodes.Single().Id;

        authorizationCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedAuthorizationCode
            {
                AuthorizationCodeId = authorizationCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [],
            })
            .Verifiable();

        const string dPoPProof = "dpop_proof_without_nonce";
        const string dPoPNonce = "dPoPNonce";
        dPoPService
            .Setup(x => x.ValidateDPoP(dPoPProof, authorizationGrant.Client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = false,
                DPoPNonce = dPoPNonce
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.AuthorizationCode,
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
        Assert.Equal(TokenError.UseDPoPNonce(dPoPNonce), processResult);
        authorizationCodeEncoder.Verify();
        dPoPService.Verify();
    }

    [Fact]
    public async Task Validate_DPoPUnequalToDPoPJkt_ExpectInvalidDPoPJktMatch()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizationCodeEncoder = new Mock<ICodeEncoder<EncodedAuthorizationCode>>();
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationCodeEncoder);
            services.AddScopedMock(dPoPService);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        var authorizationCodeId = authorizationGrant.AuthorizationCodes.Single().Id;

        authorizationCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedAuthorizationCode
            {
                AuthorizationCodeId = authorizationCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                DPoPJkt = "jkt",
                Scope = [],
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
            GrantType = GrantTypeConstants.AuthorizationCode,
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
        authorizationCodeEncoder.Verify();
        dPoPService.Verify();
    }

    [Fact]
    public async Task Validate_UnauthorizedScopeForClient_ExpectUnauthorizedForScope()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizationCodeEncoder = new Mock<ICodeEncoder<EncodedAuthorizationCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        authorizationGrant.Client.Scopes.Remove(await GetScope(ScopeConstants.Profile));
        var authorizationCodeId = authorizationGrant.AuthorizationCodes.Single().Id;
        await SaveChangesAsync();

        authorizationCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedAuthorizationCode
            {
                AuthorizationCodeId = authorizationCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [ScopeConstants.Profile],
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.AuthorizationCode,
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
        Assert.Equal(TokenError.UnauthorizedForScope, processResult);
        authorizationCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_NoConsentedScope_ExpectConsentRequired()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizationCodeEncoder = new Mock<ICodeEncoder<EncodedAuthorizationCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        authorizationGrant.AuthorizationGrantConsents.Clear();
        var authorizationCodeId = authorizationGrant.AuthorizationCodes.Single().Id;
        await SaveChangesAsync();

        authorizationCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedAuthorizationCode
            {
                AuthorizationCodeId = authorizationCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [ScopeConstants.OpenId]
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.AuthorizationCode,
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
        authorizationCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_ExceedConsentedScope_ExpectScopeExceedsConsentedScope()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizationCodeEncoder = new Mock<ICodeEncoder<EncodedAuthorizationCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

        var weatherClient = await GetWeatherClient();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        var authorizationCodeId = authorizationGrant.AuthorizationCodes.Single().Id;

        authorizationCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedAuthorizationCode
            {
                AuthorizationCodeId = authorizationCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [ScopeConstants.OpenId, ScopeConstants.Profile]
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.AuthorizationCode,
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
        authorizationCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_ExceedConsentedScopeWithResource_ExpectScopeExceedsConsentedScope()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizationCodeEncoder = new Mock<ICodeEncoder<EncodedAuthorizationCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        var authorizationCodeId = authorizationGrant.AuthorizationCodes.Single().Id;

        authorizationCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedAuthorizationCode
            {
                AuthorizationCodeId = authorizationCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [ScopeConstants.OpenId]
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.AuthorizationCode,
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
        var authorizationCodeEncoder = new Mock<ICodeEncoder<EncodedAuthorizationCode>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationCodeEncoder);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        authorizationGrant.Client.RequireConsent = false;
        authorizationGrant.AuthorizationGrantConsents.Clear();
        var authorizationCodeId = authorizationGrant.AuthorizationCodes.Single().Id;
        await SaveChangesAsync();

        authorizationCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedAuthorizationCode
            {
                AuthorizationCodeId = authorizationCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                Scope = [ScopeConstants.OpenId]
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.AuthorizationCode,
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
        authorizationCodeEncoder.Verify();
    }

    [Fact]
    public async Task Validate_ValidatedRequest_ExpectValidatedRequest()
    {
        // Arrange
        var proofKey = ProofKeyGenerator.GetProofKeyForCodeExchange();
        var authorizationCodeEncoder = new Mock<ICodeEncoder<EncodedAuthorizationCode>>();
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationCodeEncoder);
            services.AddScopedMock(dPoPService);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(32);
        var authorizationGrant = await GetAuthorizationGrant(plainSecret);
        var redirectUri = authorizationGrant.Client.RedirectUris.Single().Uri;
        var authorizationCodeId = authorizationGrant.AuthorizationCodes.Single().Id;
        var weatherClient = await GetWeatherClient();

        const string dPoPJkt = "jkt";
        const string dPoP = "dpop";

        authorizationCodeEncoder
            .Setup(x => x.Decode(It.IsAny<string>()))
            .Returns(new EncodedAuthorizationCode
            {
                AuthorizationCodeId = authorizationCodeId,
                AuthorizationGrantId = authorizationGrant.Id,
                CodeChallenge = proofKey.CodeChallenge,
                CodeChallengeMethod = proofKey.CodeChallengeMethod,
                DPoPJkt = "jkt",
                RedirectUri = redirectUri,
                Scope = [ScopeConstants.OpenId]
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
            GrantType = GrantTypeConstants.AuthorizationCode,
            Resource = [weatherClient.ClientUri!],
            CodeVerifier = proofKey.CodeVerifier,
            RedirectUri = redirectUri,
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
        Assert.Equal(authorizationGrant.Id, processResult.Value!.AuthorizationGrantId);
        Assert.Equal(authorizationCodeId, processResult.Value!.AuthorizationCodeId);
        Assert.Equal(request.Resource, processResult.Value!.Resource);
        Assert.Equal([ScopeConstants.OpenId], processResult.Value!.Scope);
        Assert.Equal(dPoPJkt, processResult.Value!.DPoPJkt);
        authorizationCodeEncoder.Verify();
        dPoPService.Verify();
    }

    private async Task<AuthorizationCodeGrant> GetAuthorizationGrant(string plainSecret)
    {
        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);

        var client = new Client("webapp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var hashedSecret = CryptographyHelper.HashPassword(plainSecret);
        client.SetSecret(hashedSecret);

        var redirectUri = new RedirectUri("https://webapp.authserver.dk/callback", client);

        var openIdScope = await GetScope(ScopeConstants.OpenId);
        var profileScope = await GetScope(ScopeConstants.Profile);
        client.Scopes.Add(openIdScope);
        client.Scopes.Add(profileScope);

        var authorizationCodeGrantType = await GetGrantType(GrantTypeConstants.AuthorizationCode);
        client.GrantTypes.Add(authorizationCodeGrantType);

        var authenticationContextReference = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, authenticationContextReference);
        var authorizationCode = new AuthorizationCode(authorizationGrant, 60);
        authorizationCode.SetRawValue("authorization_code");

        var scopeConsent = new ScopeConsent(subjectIdentifier, client, openIdScope);
        var authorizationGrantScopeConsent = new AuthorizationGrantScopeConsent(
            scopeConsent, authorizationGrant, "https://weather.authserver.dk");

        await AddEntity(redirectUri);
        await AddEntity(authorizationCode);
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
