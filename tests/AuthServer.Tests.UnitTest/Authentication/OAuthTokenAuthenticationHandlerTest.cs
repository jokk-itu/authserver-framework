using System.Reflection;
using AuthServer.Authentication.OAuthToken;
using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Enums;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Authentication;

public class OAuthTokenAuthenticationHandlerTest : BaseUnitTest
{
    public OAuthTokenAuthenticationHandlerTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task HandleAuthenticateAsync_NoAuthorizationHeader_ExpectNoResult()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider
        };

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        Assert.True(result.None);
        Assert.Null(result.Failure);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_NoBearerScheme_ExpectNoResult()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = "Basic username:password"
                }
            },
            RequestServices = serviceProvider
        };

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        Assert.True(result.None);
        Assert.Null(result.Failure);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_InvalidJwt_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var encodedJson = Convert.ToBase64String("{}"u8.ToArray());
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"Bearer {encodedJson}.{encodedJson}.{encodedJson}"
                }
            },
            RequestServices = serviceProvider
        };

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        Assert.NotNull(result.Failure);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ValidJwt_ExpectClaimsPrincipal()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var token = JwtBuilder.GetAccessToken("client_id");
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"Bearer {token}"
                }
            },
            RequestServices = serviceProvider
        };

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        Assert.NotNull(result.Principal);

        var accessToken = await httpContext.GetTokenAsync(Parameter.AccessToken);
        Assert.Equal(token, accessToken);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_UnknownReferenceToken_ExpectNoResult()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = "Bearer unknown_token"
                }
            },
            RequestServices = serviceProvider
        };

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        Assert.True(result.None);
        Assert.Null(result.Failure);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_IncorrectAudienceReferenceToken_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var token = new ClientAccessToken(client, "aud", "iss", null, 3600);
        await AddEntity(token);

        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"Bearer {token.Reference}"
                }
            },
            RequestServices = serviceProvider
        };

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        Assert.NotNull(result.Failure);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_RevokedReferenceToken_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var token = new ClientAccessToken(client, DiscoveryDocument.Issuer, "iss", null, 3600);
        token.Revoke();
        await AddEntity(token);

        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"Bearer {token.Reference}"
                }
            },
            RequestServices = serviceProvider
        };

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        Assert.NotNull(result.Failure);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_IssuedAtInTheFutureReferenceToken_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var token = new ClientAccessToken(client, DiscoveryDocument.Issuer, "iss", null, 3600);
        typeof(Token)
            .GetProperty(nameof(Token.IssuedAt))!
            .SetValue(token, DateTime.UtcNow.AddSeconds(60));

        await AddEntity(token);

        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"Bearer {token.Reference}"
                }
            },
            RequestServices = serviceProvider
        };

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        Assert.NotNull(result.Failure);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ExpiredReferenceToken_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var token = new ClientAccessToken(client, DiscoveryDocument.Issuer, "iss", null, 3600);
        typeof(Token)
            .GetProperty(nameof(Token.ExpiresAt))!
            .SetValue(token, DateTime.UtcNow.AddSeconds(-60));

        await AddEntity(token);

        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"Bearer {token.Reference}"
                }
            },
            RequestServices = serviceProvider
        };

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        Assert.NotNull(result.Failure);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ValidReferenceToken_ExpectClaimsPrincipal()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var token = new ClientAccessToken(client, DiscoveryDocument.Issuer, "iss", "scope", 3600);
        await AddEntity(token);

        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"Bearer {token.Reference}"
                }
            },
            RequestServices = serviceProvider
        };

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        Assert.NotNull(result.Principal);

        var accessToken = await httpContext.GetTokenAsync(Parameter.AccessToken);
        Assert.Equal(token.Reference, accessToken);
    }
}