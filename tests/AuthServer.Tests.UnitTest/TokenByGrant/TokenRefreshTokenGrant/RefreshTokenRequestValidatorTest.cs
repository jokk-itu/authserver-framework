using AuthServer.Authentication.Models;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Extensions;
using AuthServer.Helpers;
using AuthServer.Tests.Core;
using AuthServer.TokenByGrant;
using AuthServer.TokenByGrant.TokenRefreshTokenGrant;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.TokenByGrant.TokenRefreshTokenGrant;

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
    public async Task Validate_NoClientAuthentication_ExpectMultipleOrNoneClientMethod()
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
            .ReturnsAsync(new DPoPValidationResult { IsValid = false, RenewDPoPNonce = true })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = refreshToken.Reference,
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
    public async Task Validate_DPoPDoesNotMatchRefreshTokenJkt_ExpectInvalidDPoPJktMatch()
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
        Assert.Equal(TokenError.InvalidDPoPJktMatch, processResult);
        dPoPService.Verify();
    }

    [Theory]
    [InlineData("ConsentNotFound")]
    [InlineData("ScopeExceedsConsent")]
    [InlineData("ResourceExceedsConsent")]
    [InlineData("UnauthorizedClientForScope")]
    [InlineData("UnauthorizedResourceForScope")]
    public async Task Validate_ScopeValidationError_ExpectTokenError(string scopeResourceError)
    {
        // Arrange
        var scopeResourceService = new Mock<IScopeResourceService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(scopeResourceService);
        });
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var refreshToken = await GetRefreshToken(client);

        var jwtRefreshToken = JwtBuilder.GetRefreshToken(
            client.Id, refreshToken.AuthorizationGrant.Id, refreshToken.Reference);

        var weatherClient = await GetWeatherClient();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = jwtRefreshToken,
            Scope = [ScopeConstants.OpenId],
            Resource = [weatherClient.ClientUri!],
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        var error = Enum.Parse<ScopeResourceError>(scopeResourceError);
        scopeResourceService
            .Setup(x => x.ValidateScopeResourceForGrant(
                request.Scope,
                request.Resource,
                refreshToken.AuthorizationGrant.Id,
                CancellationToken.None))
            .ReturnsAsync(new ScopeResourceValidationResult
            {
                Error = error
            })
            .Verifiable();

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.False(processResult.IsSuccess);
        Assert.NotNull(processResult.Error);
        scopeResourceService.Verify();
    }

    [Fact]
    public async Task Validate_ScopeDoesNotContainOfflineAccess_ExpectOfflineAccessScopeRequired()
    {
        // Arrange
        var scopeResourceService = new Mock<IScopeResourceService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(scopeResourceService);
        });
        var refreshTokenRequestValidator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>>();

        var plainSecret = CryptographyHelper.GetRandomString(16);
        var client = await GetClient(plainSecret);

        var refreshToken = await GetRefreshToken(client);

        var jwtRefreshToken = JwtBuilder.GetRefreshToken(
            client.Id, refreshToken.AuthorizationGrant.Id, refreshToken.Reference);

        var weatherClient = await GetWeatherClient();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.RefreshToken,
            RefreshToken = jwtRefreshToken,
            Scope = [ScopeConstants.OpenId],
            Resource = [weatherClient.ClientUri!],
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        scopeResourceService
            .Setup(x => x.ValidateScopeResourceForGrant(
                request.Scope,
                request.Resource,
                refreshToken.AuthorizationGrant.Id,
                CancellationToken.None))
            .ReturnsAsync(new ScopeResourceValidationResult
            {
                Scopes = [ScopeConstants.OpenId]
            })
            .Verifiable();

        // Act
        var processResult = await refreshTokenRequestValidator.Validate(request, CancellationToken.None);

        // Assert
        Assert.False(processResult.IsSuccess);
        Assert.Equal(TokenError.OfflineAccessScopeRequired, processResult.Error);
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
            client.Id, refreshToken.AuthorizationGrant.Id, refreshToken.Reference);

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
            Scope = [ScopeConstants.OpenId, ScopeConstants.OfflineAccess],
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
        Assert.Equal([ScopeConstants.OpenId, ScopeConstants.OfflineAccess], processResult.Value!.Scope);
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
        var profileScope = await GetScope(ScopeConstants.Profile);
        client.Scopes.Add(openIdScope);
        client.Scopes.Add(profileScope);

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
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);
        var refreshToken = new RefreshToken(authorizationGrant, client.Id, DiscoveryDocument.Issuer, ScopeConstants.OpenId, expiration ?? 3600)
        {
            Jkt = jkt
        };
        await AddEntity(refreshToken);

        var openIdScope = await GetScope(ScopeConstants.OpenId);
        
        var openIdScopeConsent = new ScopeConsent(subjectIdentifier, client, openIdScope);
        var authorizationGrantOpenIdScopeConsent = new AuthorizationGrantScopeConsent(openIdScopeConsent, authorizationGrant, "https://weather.authserver.dk");
        await AddEntity(authorizationGrantOpenIdScopeConsent);

        var offlineAccessScope = await GetScope(ScopeConstants.OfflineAccess);
        var offlineAccessScopeConsent = new ScopeConsent(subjectIdentifier, client, offlineAccessScope);
        var authorizationGrantOfflineAccessScopeConsent = new AuthorizationGrantScopeConsent(offlineAccessScopeConsent, authorizationGrant, "https://weather.authserver.dk");
        await AddEntity(authorizationGrantOfflineAccessScopeConsent);

        return refreshToken;
    }
}