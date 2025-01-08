using System.Security.Cryptography;
using AuthServer.Authentication.OAuthToken;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
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
    public async Task HandleAuthenticateAsync_ExpiredJwt_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();

        var key = JwksDocument.GetTokenSigningKey();
        var signingCredentials = new SigningCredentials(key.Key, key.Alg.GetDescription());
        var now = DateTime.UtcNow;
        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = DiscoveryDocument.Issuer,
            NotBefore = now,
            Expires = now.AddSeconds(-3600),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = DiscoveryDocument.Issuer,
            TokenType = TokenTypeHeaderConstants.AccessToken
        });

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
        Assert.NotNull(result.Failure);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_InvalidIssuerJwt_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();

        var key = JwksDocument.GetTokenSigningKey();
        var signingCredentials = new SigningCredentials(key.Key, key.Alg.GetDescription());
        var now = DateTime.UtcNow;
        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "invalid_issuer",
            NotBefore = now,
            Expires = now.AddSeconds(3600),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = DiscoveryDocument.Issuer,
            TokenType = TokenTypeHeaderConstants.AccessToken
        });

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
        Assert.NotNull(result.Failure);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_InvalidAudienceJwt_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();

        var key = JwksDocument.GetTokenSigningKey();
        var signingCredentials = new SigningCredentials(key.Key, key.Alg.GetDescription());
        var now = DateTime.UtcNow;
        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = DiscoveryDocument.Issuer,
            NotBefore = now,
            Expires = now.AddSeconds(3600),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = "invalid_audience",
            TokenType = TokenTypeHeaderConstants.AccessToken
        });

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
        Assert.NotNull(result.Failure);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_InvalidSignatureKeyJwt_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();

        var invalidKey = new RsaSecurityKey(RSA.Create(3072));
        var signingCredentials = new SigningCredentials(invalidKey, JwsAlgConstants.RsaSha256);
        var now = DateTime.UtcNow;
        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = DiscoveryDocument.Issuer,
            NotBefore = now,
            Expires = now.AddSeconds(3600),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = DiscoveryDocument.Issuer,
            TokenType = TokenTypeHeaderConstants.AccessToken
        });

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
        Assert.NotNull(result.Failure);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_InvalidSignatureAlgorithmJwt_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();

        var key = JwksDocument.GetTokenSigningKey();
        var invalidAlg = JwsAlgConstants.RsaSha512;
        var signingCredentials = new SigningCredentials(key.Key, invalidAlg);
        var now = DateTime.UtcNow;
        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = DiscoveryDocument.Issuer,
            NotBefore = now,
            Expires = now.AddSeconds(3600),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = DiscoveryDocument.Issuer,
            TokenType = TokenTypeHeaderConstants.AccessToken
        });

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
        Assert.NotNull(result.Failure);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_InvalidTypHeaderJwt_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();

        var key = JwksDocument.GetTokenSigningKey();
        var signingCredentials = new SigningCredentials(key.Key, key.Alg.GetDescription());
        var now = DateTime.UtcNow;
        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = DiscoveryDocument.Issuer,
            NotBefore = now,
            Expires = now.AddSeconds(3600),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = DiscoveryDocument.Issuer,
            TokenType = "invalid_typ"
        });

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
        Assert.NotNull(result.Failure);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_InvalidNotBeforeJwt_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();

        var key = JwksDocument.GetTokenSigningKey();
        var signingCredentials = new SigningCredentials(key.Key, key.Alg.GetDescription());
        var now = DateTime.UtcNow;
        var token = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = DiscoveryDocument.Issuer,
            NotBefore = now.AddSeconds(3600),
            Expires = now.AddSeconds(3600),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = DiscoveryDocument.Issuer,
            TokenType = TokenTypeHeaderConstants.AccessToken
        });

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

    [Fact]
    public async Task HandleChallengeAsync_NoBearerToken_ExpectInvalidRequest()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var httpContext = new DefaultHttpContext
        {
            RequestServices = serviceProvider
        };

        // Act
        await httpContext.ChallengeAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        Assert.Equal(StatusCodes.Status401Unauthorized, httpContext.Response.StatusCode);
        Assert.Equal("Bearer error=\"invalid_request\"", httpContext.Response.Headers.WWWAuthenticate);
    }

    [Fact]
    public async Task HandleChallengeAsync_InvalidBearerToken_ExpectInvalidToken()
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
        await httpContext.ChallengeAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        Assert.Equal(StatusCodes.Status401Unauthorized, httpContext.Response.StatusCode);
        Assert.Equal("Bearer error=\"invalid_token\"", httpContext.Response.Headers.WWWAuthenticate);
    }

    [Fact]
    public async Task HandleForbidAsync_Unauthorized_ExpectInsufficientScope()
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
        await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);
        await httpContext.ForbidAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        Assert.Equal(StatusCodes.Status403Forbidden, httpContext.Response.StatusCode);
        Assert.Equal("Bearer error=\"insufficient_scope\"", httpContext.Response.Headers.WWWAuthenticate);
    }
}