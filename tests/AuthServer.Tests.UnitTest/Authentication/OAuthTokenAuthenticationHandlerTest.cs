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
using System.Security.Cryptography;
using AuthServer.Authentication.Abstractions;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Helpers;
using AuthServer.Tests.Core;
using Moq;
using Xunit.Abstractions;
using Claim = System.Security.Claims.Claim;

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
    public async Task HandleAuthenticateAsync_NoBearerValue_ExpectNoResult()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = TokenTypeSchemaConstants.Bearer
                }
            },
            RequestServices = serviceProvider
        };

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidRequest, ((OAuthTokenException)result.Failure).Error);
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
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidToken, ((OAuthTokenException)result.Failure).Error);
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
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidToken, ((OAuthTokenException)result.Failure).Error);
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
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidToken, ((OAuthTokenException)result.Failure).Error);
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
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidToken, ((OAuthTokenException)result.Failure).Error);
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
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidToken, ((OAuthTokenException)result.Failure).Error);
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
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidToken, ((OAuthTokenException)result.Failure).Error);
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
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidToken, ((OAuthTokenException)result.Failure).Error);
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
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidToken, ((OAuthTokenException)result.Failure).Error);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_BearerSchemeDPoPBoundTokenJwt_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var token = JwtBuilder.GetAccessToken("client_id", "jkt");
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
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidToken, ((OAuthTokenException)result.Failure).Error);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_DPoPSchemeBearerTokenJwt_ExpectFailure()
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
                    Authorization = $"DPoP {token}"
                }
            },
            RequestServices = serviceProvider
        };

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidToken, ((OAuthTokenException)result.Failure).Error);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_InvalidDPoPHeaderJwt_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var token = JwtBuilder.GetAccessToken("client_id", "jkt");
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"DPoP {token}"
                }
            },
            RequestServices = serviceProvider
        };

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidRequest, ((OAuthTokenException)result.Failure).Error);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_InvalidDPoPTokenJwt_ExpectFailure()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });

        const string clientId = "client_id";
        var token = JwtBuilder.GetAccessToken(clientId, "jkt");
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"DPoP {token}"
                }
            },
            RequestServices = serviceProvider
        };

        const string dPoPToken = "dpop";

        httpContext.Request.Headers.Append(Parameter.DPoP, dPoPToken);

        dPoPService
            .Setup(x => x.ValidateDPoP(dPoPToken, clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = false
            })
            .Verifiable();

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        dPoPService.Verify();
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidDPoPProof, ((OAuthTokenException)result.Failure).Error);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ExistingDPoPNonceJwt_ExpectDPoPNonceFailure()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });

        const string clientId = "client_id";
        var token = JwtBuilder.GetAccessToken(clientId, "jkt");
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"DPoP {token}"
                }
            },
            RequestServices = serviceProvider
        };

        const string dPoPToken = "dpop";
        const string dPoPNonce = "dpop_nonce";

        httpContext.Request.Headers.Append(Parameter.DPoP, dPoPToken);

        dPoPService
            .Setup(x => x.ValidateDPoP(dPoPToken, clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = false,
                DPoPNonce = dPoPNonce
            })
            .Verifiable();

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        dPoPService.Verify();
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.UseDPoPNonce, ((OAuthTokenException)result.Failure).Error);
        Assert.Equal(dPoPNonce, ((OAuthTokenException)result.Failure).DPoPNonce);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_InvalidDPoPNonceJwt_ExpectDPoPNonceFailure()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);

        var token = JwtBuilder.GetAccessToken(client.Id, "jkt");
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"DPoP {token}"
                }
            },
            RequestServices = serviceProvider
        };

        const string dPoPToken = "dpop";

        httpContext.Request.Headers.Append(Parameter.DPoP, dPoPToken);

        dPoPService
            .Setup(x => x.ValidateDPoP(dPoPToken, client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = false,
                RenewDPoPNonce = true
            })
            .Verifiable();

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        dPoPService.Verify();
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.UseDPoPNonce, ((OAuthTokenException)result.Failure).Error);
        Assert.Single(client.Nonces, x => x.Value == ((OAuthTokenException)result.Failure).DPoPNonce);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_MismatchAccessTokenHashJwt_ExpectFailure()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });

        const string clientId = "client_id";
        var token = JwtBuilder.GetAccessToken(clientId, "jkt");
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"DPoP {token}"
                }
            },
            RequestServices = serviceProvider
        };

        const string dPoPToken = "dpop";

        httpContext.Request.Headers.Append(Parameter.DPoP, dPoPToken);

        dPoPService
            .Setup(x => x.ValidateDPoP(dPoPToken, clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = true,
                AccessTokenHash = "invalid_access_token_hash"
            })
            .Verifiable();

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        dPoPService.Verify();
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidToken, ((OAuthTokenException)result.Failure).Error);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_MismatchJktJwt_ExpectFailure()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });

        const string clientId = "client_id";
        var token = JwtBuilder.GetAccessToken(clientId, "jkt");
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"DPoP {token}"
                }
            },
            RequestServices = serviceProvider
        };

        const string dPoPToken = "dpop";

        httpContext.Request.Headers.Append(Parameter.DPoP, dPoPToken);

        dPoPService
            .Setup(x => x.ValidateDPoP(dPoPToken, clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = true,
                AccessTokenHash = CryptographyHelper.HashToken(token),
                DPoPJkt = "invalid_jkt"
            })
            .Verifiable();

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        dPoPService.Verify();
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidToken, ((OAuthTokenException)result.Failure).Error);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ValidDPoPJwt_ExpectClaimsPrincipal()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });

        const string clientId = "client_id";
        const string jkt = "jkt";
        var token = JwtBuilder.GetAccessToken(clientId, jkt);
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"DPoP {token}"
                }
            },
            RequestServices = serviceProvider
        };

        const string dPoPToken = "dpop";

        httpContext.Request.Headers.Append(Parameter.DPoP, dPoPToken);

        dPoPService
            .Setup(x => x.ValidateDPoP(dPoPToken, clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = true,
                AccessTokenHash = CryptographyHelper.HashToken(token),
                DPoPJkt = jkt
            })
            .Verifiable();

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        dPoPService.Verify();
        Assert.False(result.None);
        Assert.Null(result.Failure);
        Assert.NotNull(result.Principal);

        var accessToken = await httpContext.GetTokenAsync(Parameter.AccessToken);
        Assert.Equal(token, accessToken);

        var tokenTypeScheme = await httpContext.GetTokenAsync("TokenTypeScheme");
        Assert.Equal(TokenTypeSchemaConstants.DPoP, tokenTypeScheme);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ValidBearerJwt_ExpectClaimsPrincipal()
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
        Assert.False(result.None);
        Assert.Null(result.Failure);
        Assert.NotNull(result.Principal);

        var accessToken = await httpContext.GetTokenAsync(Parameter.AccessToken);
        Assert.Equal(token, accessToken);

        var tokenTypeScheme = await httpContext.GetTokenAsync("TokenTypeScheme");
        Assert.Equal(TokenTypeSchemaConstants.Bearer, tokenTypeScheme);
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
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidToken, ((OAuthTokenException)result.Failure).Error);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_IncorrectAudienceReferenceToken_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var token = new ClientAccessToken(client, "aud", "iss", null, 3600, null);
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
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidToken, ((OAuthTokenException)result.Failure).Error);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_RevokedReferenceToken_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var token = new ClientAccessToken(client, DiscoveryDocument.Issuer, "iss", null, 3600, null);
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
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidToken, ((OAuthTokenException)result.Failure).Error);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_IssuedAtInTheFutureReferenceToken_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var token = new ClientAccessToken(client, DiscoveryDocument.Issuer, "iss", null, 3600, null);
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
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidToken, ((OAuthTokenException)result.Failure).Error);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ExpiredReferenceToken_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var token = new ClientAccessToken(client, DiscoveryDocument.Issuer, "iss", null, 3600, null);
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
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidToken, ((OAuthTokenException)result.Failure).Error);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_BearerSchemeDPoPTokenReferenceToken_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var token = new ClientAccessToken(client, DiscoveryDocument.Issuer, "iss", null, 3600, "jkt");
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
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidToken, ((OAuthTokenException)result.Failure).Error);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_DPoPSchemeBearerTokenReferenceToken_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var token = new ClientAccessToken(client, DiscoveryDocument.Issuer, "iss", null, 3600, null);
        await AddEntity(token);

        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"DPoP {token.Reference}"
                }
            },
            RequestServices = serviceProvider
        };

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidToken, ((OAuthTokenException)result.Failure).Error);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_InvalidDPoPHeaderReferenceToken_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var token = new ClientAccessToken(client, DiscoveryDocument.Issuer, "iss", null, 3600, "jkt");
        await AddEntity(token);

        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"DPoP {token.Reference}"
                }
            },
            RequestServices = serviceProvider
        };

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidRequest, ((OAuthTokenException)result.Failure).Error);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_InvalidDPoPTokenReferenceToken_ExpectFailure()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var token = new ClientAccessToken(client, DiscoveryDocument.Issuer, "iss", null, 3600, "jkt");
        await AddEntity(token);

        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"DPoP {token.Reference}"
                }
            },
            RequestServices = serviceProvider
        };

        const string dPoPToken = "dpop";

        httpContext.Request.Headers.Append(Parameter.DPoP, dPoPToken);

        dPoPService
            .Setup(x => x.ValidateDPoP(dPoPToken, client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = false
            })
            .Verifiable();

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        dPoPService.Verify();
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidDPoPProof, ((OAuthTokenException)result.Failure).Error);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ExistingDPoPNonceReferenceToken_ExpectDPoPNonceFailure()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var token = new ClientAccessToken(client, DiscoveryDocument.Issuer, "iss", null, 3600, "jkt");
        await AddEntity(token);

        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"DPoP {token.Reference}"
                }
            },
            RequestServices = serviceProvider
        };

        const string dPoPToken = "dpop";
        const string dPoPNonce = "dpop-nonce";

        httpContext.Request.Headers.Append(Parameter.DPoP, dPoPToken);

        dPoPService
            .Setup(x => x.ValidateDPoP(dPoPToken, client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = false,
                DPoPNonce = dPoPNonce
            })
            .Verifiable();

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        dPoPService.Verify();
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.UseDPoPNonce, ((OAuthTokenException)result.Failure).Error);
        Assert.Equal(dPoPNonce, ((OAuthTokenException)result.Failure).DPoPNonce);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_InvalidDPoPNonceReferenceToken_ExpectDPoPNonceFailure()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var token = new ClientAccessToken(client, DiscoveryDocument.Issuer, "iss", null, 3600, "jkt");
        await AddEntity(token);

        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"DPoP {token.Reference}"
                }
            },
            RequestServices = serviceProvider
        };

        const string dPoPToken = "dpop";

        httpContext.Request.Headers.Append(Parameter.DPoP, dPoPToken);

        dPoPService
            .Setup(x => x.ValidateDPoP(dPoPToken, client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = false,
                RenewDPoPNonce = true
            })
            .Verifiable();

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        dPoPService.Verify();
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.UseDPoPNonce, ((OAuthTokenException)result.Failure).Error);
        Assert.Single(client.Nonces, x => x.Value == ((OAuthTokenException)result.Failure).DPoPNonce);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_MismatchAccessTokenHashReferenceToken_ExpectFailure()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var token = new ClientAccessToken(client, DiscoveryDocument.Issuer, "iss", null, 3600, "jkt");
        await AddEntity(token);

        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"DPoP {token.Reference}"
                }
            },
            RequestServices = serviceProvider
        };

        const string dPoPToken = "dpop";

        httpContext.Request.Headers.Append(Parameter.DPoP, dPoPToken);

        dPoPService
            .Setup(x => x.ValidateDPoP(dPoPToken, client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = true,
                AccessTokenHash = "invalid_token_hash"
            })
            .Verifiable();

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        dPoPService.Verify();
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidToken, ((OAuthTokenException)result.Failure).Error);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_MismatchJktReferenceToken_ExpectFailure()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var token = new ClientAccessToken(client, DiscoveryDocument.Issuer, "iss", null, 3600, "jkt");
        await AddEntity(token);

        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"DPoP {token.Reference}"
                }
            },
            RequestServices = serviceProvider
        };

        const string dPoPToken = "dpop";

        httpContext.Request.Headers.Append(Parameter.DPoP, dPoPToken);

        dPoPService
            .Setup(x => x.ValidateDPoP(dPoPToken, client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = true,
                AccessTokenHash = CryptographyHelper.HashToken(token.Reference),
                DPoPJkt = "invalid_jkt"
            })
            .Verifiable();

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        dPoPService.Verify();
        Assert.False(result.None);
        Assert.NotNull(result.Failure);
        Assert.IsType<OAuthTokenException>(result.Failure);
        Assert.Equal(ErrorCode.InvalidToken, ((OAuthTokenException)result.Failure).Error);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ValidDPoPReferenceToken_ExpectClaimsPrincipal()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });
        const string jkt = "jkt";
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var token = new ClientAccessToken(client, DiscoveryDocument.Issuer, "iss", null, 3600, jkt);
        await AddEntity(token);

        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"DPoP {token.Reference}"
                }
            },
            RequestServices = serviceProvider
        };

        const string dPoPToken = "dpop";

        httpContext.Request.Headers.Append(Parameter.DPoP, dPoPToken);

        dPoPService
            .Setup(x => x.ValidateDPoP(dPoPToken, client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = true,
                AccessTokenHash = CryptographyHelper.HashToken(token.Reference),
                DPoPJkt = jkt
            })
            .Verifiable();

        // Act
        var result = await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        dPoPService.Verify();
        Assert.False(result.None);
        Assert.Null(result.Failure);
        Assert.NotNull(result.Principal);

        var accessToken = await httpContext.GetTokenAsync(Parameter.AccessToken);
        Assert.Equal(token.Reference, accessToken);

        var tokenTypeScheme = await httpContext.GetTokenAsync("TokenTypeScheme");
        Assert.Equal(TokenTypeSchemaConstants.DPoP, tokenTypeScheme);
    }

    [Fact]
    public async Task HandleAuthenticateAsync_ValidBearerReferenceToken_ExpectClaimsPrincipal()
    {
        // Arrange
        var userClaimService = new Mock<IUserClaimService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(userClaimService);
        });

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);
        var token = new GrantAccessToken(authorizationGrant, DiscoveryDocument.Issuer, DiscoveryDocument.Issuer, "scope", 300, null);
        await AddEntity(token);

        userClaimService
            .Setup(x => x.GetClaims(subjectIdentifier.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new List<Claim>())
            .Verifiable();

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
        userClaimService.Verify();
        Assert.False(result.None);
        Assert.Null(result.Failure);
        Assert.NotNull(result.Principal);

        var accessToken = await httpContext.GetTokenAsync(Parameter.AccessToken);
        Assert.Equal(token.Reference, accessToken);

        var tokenTypeScheme = await httpContext.GetTokenAsync("TokenTypeScheme");
        Assert.Equal(TokenTypeSchemaConstants.Bearer, tokenTypeScheme);
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
        var dPoPAlgs = string.Join(' ', DiscoveryDocument.DPoPSigningAlgValuesSupported);
        Assert.Equal($"Bearer, DPoP algs=\"{dPoPAlgs}\"", httpContext.Response.Headers.WWWAuthenticate);
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
        var dPoPAlgs = string.Join(' ', DiscoveryDocument.DPoPSigningAlgValuesSupported);
        Assert.Equal($"Bearer error=\"invalid_token\", error_description=\"token is not valid\", DPoP algs=\"{dPoPAlgs}\"", httpContext.Response.Headers.WWWAuthenticate);
    }

    [Fact]
    public async Task HandleChallengeAsync_InvalidDPoPToken_ExpectInvalidToken()
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
                    Authorization = $"DPoP {encodedJson}.{encodedJson}.{encodedJson}"
                }
            },
            RequestServices = serviceProvider
        };

        // Act
        await httpContext.ChallengeAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        Assert.Equal(StatusCodes.Status401Unauthorized, httpContext.Response.StatusCode);
        var dPoPAlgs = string.Join(' ', DiscoveryDocument.DPoPSigningAlgValuesSupported);
        Assert.Equal($"Bearer, DPoP algs=\"{dPoPAlgs}\", error=\"invalid_token\", error_description=\"token is not valid\"", httpContext.Response.Headers.WWWAuthenticate);
    }

    [Fact]
    public async Task HandleChallengeAsync_InvalidDPoPNonce_ExpectUseDPoPNonce()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });

        const string clientId = "client_id";
        const string jkt = "jkt";
        var token = JwtBuilder.GetAccessToken(clientId, jkt);
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"DPoP {token}"
                }
            },
            RequestServices = serviceProvider
        };

        const string dPoPToken = "dpop";
        const string dPoPNonce = "dpop_nonce";

        httpContext.Request.Headers.Append(Parameter.DPoP, dPoPToken);

        dPoPService
            .Setup(x => x.ValidateDPoP(dPoPToken, clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = false,
                DPoPNonce = dPoPNonce
            })
            .Verifiable();

        // Act
        await httpContext.ChallengeAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        Assert.Equal(StatusCodes.Status401Unauthorized, httpContext.Response.StatusCode);
        var dPoPAlgs = string.Join(' ', DiscoveryDocument.DPoPSigningAlgValuesSupported);
        Assert.Equal($"Bearer, DPoP algs=\"{dPoPAlgs}\", error=\"{ErrorCode.UseDPoPNonce}\", error_description=\"use the provided DPoP nonce\"", httpContext.Response.Headers.WWWAuthenticate);
        Assert.Equal(dPoPNonce, httpContext.Response.Headers.GetValue(Parameter.DPoPNonce));
    }

    [Fact]
    public async Task HandleForbidAsync_UnauthorizedBearerToken_ExpectCustomError()
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
        await httpContext.ForbidAsync(
            OAuthTokenAuthenticationDefaults.AuthenticationScheme,
            new AuthenticationProperties(null, new Dictionary<string, object?>
            {
                { OAuthTokenAuthenticationDefaults.ErrorParameter, ErrorCode.AccessDenied },
                { OAuthTokenAuthenticationDefaults.ErrorDescriptionParameter, "access is denied" }
            }));

        // Assert
        Assert.Equal(StatusCodes.Status403Forbidden, httpContext.Response.StatusCode);
        var dPoPAlgs = string.Join(' ', DiscoveryDocument.DPoPSigningAlgValuesSupported);
        Assert.Equal($"Bearer error=\"{ErrorCode.AccessDenied}\", error_description=\"access is denied\", DPoP algs=\"{dPoPAlgs}\"", httpContext.Response.Headers.WWWAuthenticate);
    }

    [Fact]
    public async Task HandleForbidAsync_UnauthorizedDPoPToken_ExpectCustomError()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });

        const string clientId = "client_id";
        const string jkt = "jkt";
        var token = JwtBuilder.GetAccessToken(clientId, jkt);
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"DPoP {token}"
                }
            },
            RequestServices = serviceProvider
        };

        const string dPoPToken = "dpop";
        httpContext.Request.Headers.Append(Parameter.DPoP, dPoPToken);

        dPoPService
            .Setup(x => x.ValidateDPoP(dPoPToken, clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = true,
                DPoPJkt = jkt,
                AccessTokenHash = CryptographyHelper.HashToken(token)
            })
            .Verifiable();

        // Act
        await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);
        await httpContext.ForbidAsync(
            OAuthTokenAuthenticationDefaults.AuthenticationScheme,
            new AuthenticationProperties(null, new Dictionary<string, object?>
            {
                { OAuthTokenAuthenticationDefaults.ErrorParameter, ErrorCode.AccessDenied },
                { OAuthTokenAuthenticationDefaults.ErrorDescriptionParameter, "access is denied" }
            }));

        // Assert
        dPoPService.Verify();
        Assert.Equal(StatusCodes.Status403Forbidden, httpContext.Response.StatusCode);
        var dPoPAlgs = string.Join(' ', DiscoveryDocument.DPoPSigningAlgValuesSupported);
        Assert.Equal($"Bearer, DPoP algs=\"{dPoPAlgs}\", error=\"{ErrorCode.AccessDenied}\", error_description=\"access is denied\"", httpContext.Response.Headers.WWWAuthenticate);
    }

    [Fact]
    public async Task HandleForbidAsync_UnauthorizedBearerToken_ExpectInsufficientScope()
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
        await httpContext.ForbidAsync(
            OAuthTokenAuthenticationDefaults.AuthenticationScheme,
            new AuthenticationProperties(null, new Dictionary<string, object?>
            {
                { OAuthTokenAuthenticationDefaults.ScopeParameter, "scope:read" }
            }));

        // Assert
        Assert.Equal(StatusCodes.Status403Forbidden, httpContext.Response.StatusCode);
        var dPoPAlgs = string.Join(' ', DiscoveryDocument.DPoPSigningAlgValuesSupported);
        Assert.Equal($"Bearer error=\"{ErrorCode.InsufficientScope}\", error_description=\"provide a token with the required scope\", scope=\"scope:read\", DPoP algs=\"{dPoPAlgs}\"", httpContext.Response.Headers.WWWAuthenticate);
    }

    [Fact]
    public async Task HandleForbidAsync_UnauthorizedDPoPToken_ExpectInsufficientScope()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });

        const string clientId = "client_id";
        const string jkt = "jkt";
        var token = JwtBuilder.GetAccessToken(clientId, jkt);
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"DPoP {token}"
                }
            },
            RequestServices = serviceProvider
        };

        const string dPoPToken = "dpop";
        httpContext.Request.Headers.Append(Parameter.DPoP, dPoPToken);

        dPoPService
            .Setup(x => x.ValidateDPoP(dPoPToken, clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = true,
                DPoPJkt = jkt,
                AccessTokenHash = CryptographyHelper.HashToken(token)
            })
            .Verifiable();

        // Act
        await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);
        await httpContext.ForbidAsync(
            OAuthTokenAuthenticationDefaults.AuthenticationScheme,
            new AuthenticationProperties(null, new Dictionary<string, object?>
            {
                { OAuthTokenAuthenticationDefaults.ScopeParameter, "scope:read" }
            }));

        // Assert
        dPoPService.Verify();
        Assert.Equal(StatusCodes.Status403Forbidden, httpContext.Response.StatusCode);
        var dPoPAlgs = string.Join(' ', DiscoveryDocument.DPoPSigningAlgValuesSupported);
        Assert.Equal($"Bearer, DPoP algs=\"{dPoPAlgs}\", error=\"{ErrorCode.InsufficientScope}\", error_description=\"provide a token with the required scope\", scope=\"scope:read\"", httpContext.Response.Headers.WWWAuthenticate);
    }

    [Fact]
    public async Task HandleForbidAsync_UnauthorizedBearerToken_ExpectInvalidToken()
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
        var dPoPAlgs = string.Join(' ', DiscoveryDocument.DPoPSigningAlgValuesSupported);
        Assert.Equal($"Bearer error=\"{ErrorCode.InvalidToken}\", error_description=\"token is invalid\", DPoP algs=\"{dPoPAlgs}\"", httpContext.Response.Headers.WWWAuthenticate);
    }

    [Fact]
    public async Task HandleForbidAsync_UnauthorizedDPoPToken_ExpectInvalidToken()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });

        const string clientId = "client_id";
        const string jkt = "jkt";
        var token = JwtBuilder.GetAccessToken(clientId, jkt);
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Headers =
                {
                    Authorization = $"DPoP {token}"
                }
            },
            RequestServices = serviceProvider
        };

        const string dPoPToken = "dpop";
        httpContext.Request.Headers.Append(Parameter.DPoP, dPoPToken);

        dPoPService
            .Setup(x => x.ValidateDPoP(dPoPToken, clientId, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = true,
                DPoPJkt = jkt,
                AccessTokenHash = CryptographyHelper.HashToken(token)
            })
            .Verifiable();

        // Act
        await httpContext.AuthenticateAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);
        await httpContext.ForbidAsync(OAuthTokenAuthenticationDefaults.AuthenticationScheme);

        // Assert
        dPoPService.Verify();
        Assert.Equal(StatusCodes.Status403Forbidden, httpContext.Response.StatusCode);
        var dPoPAlgs = string.Join(' ', DiscoveryDocument.DPoPSigningAlgValuesSupported);
        Assert.Equal($"Bearer, DPoP algs=\"{dPoPAlgs}\", error=\"{ErrorCode.InvalidToken}\", error_description=\"token is invalid\"", httpContext.Response.Headers.WWWAuthenticate);
    }
}