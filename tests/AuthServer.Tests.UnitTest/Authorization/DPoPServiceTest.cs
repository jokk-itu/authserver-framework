using AuthServer.Authorization.Abstractions;
using AuthServer.Constants;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Helpers;
using AuthServer.Tests.Core;
using AuthServer.TokenDecoders;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Authorization;
public class DPoPServiceTest : BaseUnitTest
{
    public DPoPServiceTest(ITestOutputHelper outputHelper) : base(outputHelper)
    {
    }

    [Fact]
    public async Task ValidateDPoP_InvalidDPoP_ExpectInvalidResult()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScoped<IHttpContextAccessor, HttpContextAccessor>(_ =>
                new HttpContextAccessor
                {
                    HttpContext = new DefaultHttpContext
                    {
                        Request =
                        {
                            Host = new HostString("localhost", 5000),
                            Scheme = "https",
                            Path = "/connect/par"
                        }
                    }
                });
        });
        var dPoPService = serviceProvider.GetRequiredService<IDPoPService>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);

        const string dPoP = "invalid_dpop";

        // Act
        var validationResult = await dPoPService.ValidateDPoP(dPoP, client.Id, CancellationToken.None);

        // Assert
        Assert.False(validationResult.IsValid);
        Assert.Null(validationResult.DPoPJkt);
        Assert.Null(validationResult.AccessTokenHash);
        Assert.False(validationResult.RenewDPoPNonce);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("GET")]
    [InlineData("invalid_http_method")]
    public async Task ValidateDPoP_InvalidHtmClaim_ExpectInvalidResult(string? htm)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(SetupHttpContext);
        var dPoPService = serviceProvider.GetRequiredService<IDPoPService>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);

        var claims = new Dictionary<string, object>();
        if (htm is not null)
        {
            claims.Add(ClaimNameConstants.Htm, htm);
        }
        var jwks = ClientJwkBuilder.GetClientJwks();
        var dPoP = JwtBuilder.GetDPoPToken(claims, client.Id, jwks, ClientTokenAudience.PushedAuthorizationEndpoint);

        // Act
        var validationResult = await dPoPService.ValidateDPoP(dPoP, client.Id, CancellationToken.None);

        // Assert
        Assert.False(validationResult.IsValid);
        Assert.Null(validationResult.DPoPJkt);
        Assert.Null(validationResult.AccessTokenHash);
        Assert.False(validationResult.RenewDPoPNonce);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("https://localhost:5000/connect/token")]
    public async Task ValidateDPoP_InvalidHtuClaim_ExpectInvalidResult(string? htu)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(SetupHttpContext);
        var dPoPService = serviceProvider.GetRequiredService<IDPoPService>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);

        var claims = new Dictionary<string, object>
        {
            { ClaimNameConstants.Htm, HttpMethod.Post.Method }
        };
        if (htu is not null)
        {
            claims.Add(ClaimNameConstants.Htu, htu);
        }
        var jwks = ClientJwkBuilder.GetClientJwks();
        var dPoP = JwtBuilder.GetDPoPToken(claims, client.Id, jwks, ClientTokenAudience.PushedAuthorizationEndpoint);

        // Act
        var validationResult = await dPoPService.ValidateDPoP(dPoP, client.Id, CancellationToken.None);

        // Assert
        Assert.False(validationResult.IsValid);
        Assert.Null(validationResult.DPoPJkt);
        Assert.Null(validationResult.AccessTokenHash);
        Assert.False(validationResult.RenewDPoPNonce);
    }

    [Fact]
    public async Task ValidateDPoP_InactiveDPoP_ExpectInvalidResultWithRenewDPoPNonce()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(SetupHttpContext);
        var dPoPService = serviceProvider.GetRequiredService<IDPoPService>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);

        var claims = new Dictionary<string, object>
        {
            { ClaimNameConstants.Htm, HttpMethod.Post.Method },
            { ClaimNameConstants.Htu, "https://localhost:5000/connect/par" }
        };
        var jwks = ClientJwkBuilder.GetClientJwks();
        var dPoP = JwtBuilder.GetDPoPToken(claims, client.Id, jwks, ClientTokenAudience.PushedAuthorizationEndpoint);

        // Act
        var validationResult = await dPoPService.ValidateDPoP(dPoP, client.Id, CancellationToken.None);
        await SaveChangesAsync();

        // Assert
        Assert.False(validationResult.IsValid);
        Assert.Null(validationResult.DPoPJkt);
        Assert.Null(validationResult.AccessTokenHash);
        Assert.True(validationResult.RenewDPoPNonce);
    }

    [Fact]
    public async Task ValidateDPoP_NullNonce_ExpectInvalidResultWithRenewDPoPNonce()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(SetupHttpContext);
        var dPoPService = serviceProvider.GetRequiredService<IDPoPService>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var nonce = CryptographyHelper.GetRandomString(16);
        var dPoPNonce = new DPoPNonce(nonce, nonce.Sha256(), client);
        await AddEntity(dPoPNonce);

        var claims = new Dictionary<string, object>
        {
            { ClaimNameConstants.Htm, HttpMethod.Post.Method },
            { ClaimNameConstants.Htu, "https://localhost:5000/connect/par" }
        };
        var jwks = ClientJwkBuilder.GetClientJwks();
        var dPoP = JwtBuilder.GetDPoPToken(claims, client.Id, jwks, ClientTokenAudience.PushedAuthorizationEndpoint);

        // Act
        var validationResult = await dPoPService.ValidateDPoP(dPoP, client.Id, CancellationToken.None);

        // Assert
        Assert.False(validationResult.IsValid);
        Assert.Null(validationResult.DPoPJkt);
        Assert.Null(validationResult.AccessTokenHash);
        Assert.True(validationResult.RenewDPoPNonce);
    }

    [Fact]
    public async Task ValidateDPoP_InvalidNonceClaim_ExpectInvalidResultWithRenewDPoPNonce()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(SetupHttpContext);
        var dPoPService = serviceProvider.GetRequiredService<IDPoPService>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var nonce = CryptographyHelper.GetRandomString(16);
        var dPoPNonce = new DPoPNonce(nonce, nonce.Sha256(), client);
        await AddEntity(dPoPNonce);

        var claims = new Dictionary<string, object>
        {
            { ClaimNameConstants.Htm, HttpMethod.Post.Method },
            { ClaimNameConstants.Htu, "https://localhost:5000/connect/par" },
            { ClaimNameConstants.Nonce, CryptographyHelper.GetRandomString(16) }
        };
        var jwks = ClientJwkBuilder.GetClientJwks();
        var dPoP = JwtBuilder.GetDPoPToken(claims, client.Id, jwks, ClientTokenAudience.PushedAuthorizationEndpoint);

        // Act
        var validationResult = await dPoPService.ValidateDPoP(dPoP, client.Id, CancellationToken.None);

        // Assert
        Assert.False(validationResult.IsValid);
        Assert.Null(validationResult.DPoPJkt);
        Assert.Null(validationResult.AccessTokenHash);
        Assert.True(validationResult.RenewDPoPNonce);
    }

    [Fact]
    public async Task ValidateDPoP_ExpiredNonceClaim_ExpectInvalidResultWithRenewDPoPNonce()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(SetupHttpContext);
        var dPoPService = serviceProvider.GetRequiredService<IDPoPService>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);

        var nonce = CryptographyHelper.GetRandomString(16);
        var dPoPNonce = new DPoPNonce(nonce, nonce.Sha256(), client);

        var expiredNonce = CryptographyHelper.GetRandomString(16);
        var expiredDPoPNonce = new DPoPNonce(expiredNonce, expiredNonce.Sha256(), client);

        typeof(DPoPNonce)
            .GetProperty(nameof(DPoPNonce.ExpiresAt))!
            .SetValue(expiredDPoPNonce, DateTime.UtcNow.AddSeconds(-60));

        await AddEntity(expiredDPoPNonce);
        await AddEntity(dPoPNonce);

        var claims = new Dictionary<string, object>
        {
            { ClaimNameConstants.Htm, HttpMethod.Post.Method },
            { ClaimNameConstants.Htu, "https://localhost:5000/connect/par" },
            { ClaimNameConstants.Nonce, expiredNonce }
        };
        var jwks = ClientJwkBuilder.GetClientJwks();
        var dPoP = JwtBuilder.GetDPoPToken(claims, client.Id, jwks, ClientTokenAudience.PushedAuthorizationEndpoint);

        // Act
        var validationResult = await dPoPService.ValidateDPoP(dPoP, client.Id, CancellationToken.None);
        await SaveChangesAsync();

        // Assert
        Assert.False(validationResult.IsValid);
        Assert.Null(validationResult.DPoPJkt);
        Assert.Null(validationResult.AccessTokenHash);
        Assert.True(validationResult.RenewDPoPNonce);
    }

    [Fact]
    public async Task ValidateDPoP_ValidDPoP_ExpectValidResultWithDPoPJkt()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(SetupHttpContext);
        var dPoPService = serviceProvider.GetRequiredService<IDPoPService>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var nonce = CryptographyHelper.GetRandomString(16);
        var dPoPNonce = new DPoPNonce(nonce, nonce.Sha256(), client);
        await AddEntity(dPoPNonce);

        const string ath = "access_token_hash";
        var claims = new Dictionary<string, object>
        {
            { ClaimNameConstants.Htm, HttpMethod.Post.Method },
            { ClaimNameConstants.Htu, "https://localhost:5000/connect/par" },
            { ClaimNameConstants.Nonce, nonce },
            { ClaimNameConstants.Ath, ath }
        };
        var jwks = ClientJwkBuilder.GetClientJwks();
        var jsonWebKey = new JsonWebKeySet(jwks.PublicJwks).Keys.First(x => x.Use == JsonWebKeyUseNames.Sig);
        var jkt = Base64UrlEncoder.Encode(jsonWebKey.ComputeJwkThumbprint());
        var dPoP = JwtBuilder.GetDPoPToken(claims, client.Id, jwks, ClientTokenAudience.PushedAuthorizationEndpoint);

        // Act
        var validationResult = await dPoPService.ValidateDPoP(dPoP, client.Id, CancellationToken.None);
        await SaveChangesAsync();

        // Assert
        Assert.True(validationResult.IsValid);
        Assert.Equal(jkt, validationResult.DPoPJkt);
        Assert.Equal(ath, validationResult.AccessTokenHash);
        Assert.False(validationResult.RenewDPoPNonce);
    }

    private static void SetupHttpContext(IServiceCollection services)
    {
        services.AddScoped<IHttpContextAccessor, HttpContextAccessor>(_ =>
            new HttpContextAccessor
            {
                HttpContext = new DefaultHttpContext
                {
                    Request =
                    {
                        Method = HttpMethod.Post.Method,
                        Host = new HostString("localhost", 5000),
                        Scheme = "https",
                        Path = "/connect/par"
                    }
                }
            });
    }
}