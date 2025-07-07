using AuthServer.Authentication.Models;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Helpers;
using AuthServer.PushedAuthorization;
using AuthServer.Tests.Core;
using AuthServer.TokenByGrant;
using AuthServer.TokenByGrant.RefreshTokenGrant;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.TokenByGrant.RefreshTokenGrant;

public class RefreshTokenRequestValidatorTest : BaseUnitTest
{
    public RefreshTokenRequestValidatorTest(ITestOutputHelper outputHelper) : base(outputHelper)
    {
    }

    [Fact]
    public async Task Validate_EmptyGrantType_ExpectUnsupportedGrantType()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var request = new TokenRequest();

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.UnsupportedGrantType, processResult);
    }

    [Fact]
    public async Task Validate_EmptyRefreshToken_ExpectInvalidRefreshToken()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken
        };

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidRefreshToken, processResult);
    }

    [Fact]
    public async Task Validate_EmptyResource_ExpectInvalidResource()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = "token"
        };

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidResource, processResult);
    }

    [Fact]
    public async Task Validate_NoClientAuthentication_ExpectMultipleOrNoneClientMethod()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = "token",
            Resource = ["resource"]
        };

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.MultipleOrNoneClientMethod, processResult);
    }

    [Fact]
    public async Task Validate_InvalidClientAuthentication_ExpectInvalidClient()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = "token",
            Resource = ["resource"],
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    "clientId",
                    "clientSecret")
            ]
        };

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidClient, processResult);
    }

    [Fact]
    public async Task Validate_InvalidJwtRefreshToken_ExpectInvalidRefreshToken()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var refreshToken = await GetRefreshToken(client);

        var jwtRefreshToken = JwtBuilder.GetRefreshToken(
            "invalid_audience", refreshToken.AuthorizationGrant.Id, refreshToken.Id.ToString());

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = jwtRefreshToken,
            Resource = ["resource"],
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidRefreshToken, processResult);
    }

    [Fact]
    public async Task Validate_ExpiredJwtRefreshToken_ExpectInvalidRefreshToken()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var refreshToken = await GetRefreshToken(client, -3600);

        var jwtRefreshToken = JwtBuilder.GetRefreshToken(
            client.Id, refreshToken.AuthorizationGrant.Id, refreshToken.Id.ToString());

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = jwtRefreshToken,
            Resource = ["resource"],
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidRefreshToken, processResult);
    }

    [Fact]
    public async Task Validate_RevokedJwtRefreshToken_ExpectInvalidRefreshToken()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var refreshToken = await GetRefreshToken(client);
        refreshToken.Revoke();
        await SaveChangesAsync();

        var jwtRefreshToken = JwtBuilder.GetRefreshToken(
            client.Id, refreshToken.AuthorizationGrant.Id, refreshToken.Id.ToString());

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = jwtRefreshToken,
            Resource = ["resource"],
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidRefreshToken, processResult);
    }

    [Fact]
    public async Task Validate_InvalidReferenceRefreshToken_ExpectInvalidRefreshToken()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        
        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = "invalid_reference",
            Resource = ["resource"],
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidRefreshToken, processResult);
    }

    [Fact]
    public async Task Validate_ExpiredReferenceRefreshToken_ExpectInvalidRefreshToken()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var refreshToken = await GetRefreshToken(client, -3600);

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = refreshToken.Reference,
            Resource = ["resource"],
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidRefreshToken, processResult);
    }

    [Fact]
    public async Task Validate_RevokedReferenceRefreshToken_ExpectInvalidRefreshToken()
    {
        var serviceProvider = BuildServiceProvider();
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var refreshToken = await GetRefreshToken(client);
        refreshToken.Revoke();
        await SaveChangesAsync();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = refreshToken.Reference,
            Resource = ["resource"],
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidRefreshToken, processResult);
    }

    [Fact]
    public async Task Validate_UnauthorizedForRefreshTokenGrant_ExpectUnauthorizedForGrantType()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        client.GrantTypes.Clear();

        var refreshToken = await GetRefreshToken(client);

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = refreshToken.Reference,
            Resource = ["resource"],
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.UnauthorizedForGrantType, processResult);
    }

    [Theory]
    [InlineData(true, null)]
    [InlineData(false, "jkt")]
    [InlineData(true, "jkt")]
    public async Task Validate_RequireDPoPWithoutDPoPProof_ExpectDPoPRequired(bool requireDPoP, string? jkt)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        client.RequireDPoPBoundAccessTokens = requireDPoP;
        await SaveChangesAsync();

        var refreshToken = await GetRefreshToken(client, null, jkt);

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = refreshToken.Reference,
            Resource = ["resource"],
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

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
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var refreshToken = await GetRefreshToken(client);

        const string dPoP = "invalid_dpop_proof";
        dPoPService
            .Setup(x => x.ValidateDPoP(dPoP, client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = false
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = refreshToken.Reference,
            Resource = ["resource"],
            DPoP = dPoP,
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidDPoP, processResult);
        dPoPService.Verify();
    }

    [Fact]
    public async Task Validate_DPoPWithoutNonceClaim_ExpectUseDPoPNonce()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var refreshToken = await GetRefreshToken(client);

        const string dPoP = "invalid_dpop_proof";
        const string dPoPNonce = "dpop_nonce";
        dPoPService
            .Setup(x => x.ValidateDPoP(dPoP, client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = false,
                DPoPNonce = dPoPNonce
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = refreshToken.Reference,
            Resource = ["resource"],
            DPoP = dPoP,
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.UseDPoPNonce(dPoPNonce), processResult);
        dPoPService.Verify();
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
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var refreshToken = await GetRefreshToken(client);

        const string dPoP = "dpop";
        dPoPService
            .Setup(x => x.ValidateDPoP(dPoP, client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult { IsValid = false, DPoPNonce = null, RenewDPoPNonce = true })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = refreshToken.Reference,
            Resource = ["resource"],
            DPoP = dPoP,
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Arrange
        dPoPService.Verify();
        Assert.False(processResult.IsSuccess);
        Assert.Equal(TokenError.RenewDPoPNonce(client.Id), processResult.Error);
    }

    [Fact]
    public async Task Validate_DPoPDoesNotMatchRefreshTokenJkt_ExpectInvalidRefreshTokenJktMatch()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var refreshToken = await GetRefreshToken(client, null, "jkt");

        const string dPoP = "dpop_proof";
        const string jkt = "invalid_jkt";
        dPoPService
            .Setup(x => x.ValidateDPoP(dPoP, client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = true,
                DPoPJkt = jkt
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = refreshToken.Reference,
            Resource = ["resource"],
            DPoP = dPoP,
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidRefreshTokenJktMatch, processResult);
        dPoPService.Verify();
    }

    [Fact]
    public async Task Validate_NoConsent_ExpectConsentRequired()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var refreshToken = await GetRefreshToken(client);
        refreshToken.AuthorizationGrant.AuthorizationGrantConsents.Clear();
        await SaveChangesAsync();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = refreshToken.Reference,
            Resource = ["resource"],
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.ConsentRequired, processResult);
    }

    [Fact]
    public async Task Validate_ConsentRequiredWithRequestScope_ExpectScopeExceedsConsentedScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var refreshToken = await GetRefreshToken(client);

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = refreshToken.Reference,
            Scope = [ScopeConstants.Profile],
            Resource = ["resource"],
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.ScopeExceedsConsentedScope, processResult);
    }

    [Fact]
    public async Task Validate_ConsentRequiredWithRequestScopeAndResource_ExpectScopeExceedsConsentedScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var refreshToken = await GetRefreshToken(client);

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = refreshToken.Reference,
            Scope = [ScopeConstants.OpenId],
            Resource = ["other_resource"],
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.ScopeExceedsConsentedScope, processResult);
    }

    [Fact]
    public async Task Validate_ConsentNotRequiredWithRequestScope_ExpectUnauthorizedForScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        client.RequireConsent = false;

        var refreshToken = await GetRefreshToken(client);

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = refreshToken.Reference,
            Scope = [ScopeConstants.Profile],
            Resource = ["resource"],
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.UnauthorizedForScope, processResult);
    }

    [Fact]
    public async Task Validate_ConsentNotRequiredWithInvalidResource_ExpectInvalidResource()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);
        client.RequireConsent = false;

        var refreshToken = await GetRefreshToken(client);

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = refreshToken.Reference,
            Resource = ["invalid_resource"],
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidResource, processResult);
    }

    [Fact]
    public async Task Validate_JwtRefreshTokenAndConsentRequired_ExpectValidatedRequest()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var refreshToken = await GetRefreshToken(client);

        var jwtRefreshToken = JwtBuilder.GetRefreshToken(
            client.Id, refreshToken.AuthorizationGrant.Id, refreshToken.Id.ToString());

        var weatherClient = await GetWeatherClient();

        const string dPoP = "dpop";
        const string dPoPJkt = "dpop_jkt";
        dPoPService
            .Setup(x => x.ValidateDPoP(dPoP, client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = true,
                DPoPJkt = dPoPJkt
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = jwtRefreshToken,
            Scope = [ScopeConstants.OpenId],
            Resource = [weatherClient.ClientUri!],
            DPoP = dPoP,
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.True(processResult.IsSuccess);
        Assert.Equal(refreshToken.AuthorizationGrant.Id, processResult.Value!.AuthorizationGrantId);
        Assert.Equal(client.Id, processResult.Value!.ClientId);
        Assert.Equal([weatherClient.ClientUri!], processResult.Value!.Resource);
        Assert.Equal([ScopeConstants.OpenId], processResult.Value!.Scope);
        Assert.Equal(dPoPJkt, processResult.Value!.DPoPJkt);
        dPoPService.Verify();
    }

    private async Task<Client> GetClient(string plainSecret)
    {
        var client = new Client("webapp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var hashedSecret = CryptographyHelper.HashPassword(plainSecret);
        client.SetSecret(hashedSecret);

        var grantType = await GetGrantType(GrantTypeConstants.RefreshToken);
        client.GrantTypes.Add(grantType);

        var openIdScope = await GetScope(ScopeConstants.OpenId);
        client.Scopes.Add(openIdScope);

        await AddEntity(client);

        return client;
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

    private async Task<RefreshToken> GetRefreshToken(Client client, int? expiration = null, string? jkt = null)
    {
        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, levelOfAssurance);
        var refreshToken = new RefreshToken(authorizationGrant, client.Id, DiscoveryDocument.Issuer, ScopeConstants.OpenId, expiration ?? 3600, jkt);
        await AddEntity(refreshToken);

        var openIdScope = await GetScope(ScopeConstants.OpenId);
        var scopeConsent = new ScopeConsent(subjectIdentifier, client, openIdScope);
        var authorizationGrantScopeConsent = new AuthorizationGrantScopeConsent(scopeConsent, authorizationGrant, "https://weather.authserver.dk");
        await AddEntity(authorizationGrantScopeConsent);

        return refreshToken;
    }
}