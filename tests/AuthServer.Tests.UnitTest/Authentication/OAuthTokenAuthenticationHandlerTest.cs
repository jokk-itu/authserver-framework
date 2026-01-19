using AuthServer.Authentication.OAuthToken;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Enums;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Helpers;
using AuthServer.Tests.Core;
using Moq;
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
    public async Task HandleAuthenticateAsync_InvalidToken_ExpectFailure()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        const string token = "token";
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
    public async Task HandleAuthenticateAsync_BearerSchemeDPoPBoundToken_ExpectFailure()
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
    public async Task HandleAuthenticateAsync_DPoPSchemeBearerToken_ExpectFailure()
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
    public async Task HandleAuthenticateAsync_InvalidDPoPHeaderToken_ExpectFailure()
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
    public async Task HandleAuthenticateAsync_InvalidDPoPTokenToken_ExpectFailure()
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
    public async Task HandleAuthenticateAsync_InvalidDPoPNonceToken_ExpectDPoPNonceFailure()
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
    public async Task HandleAuthenticateAsync_MismatchAccessTokenHashToken_ExpectFailure()
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
    public async Task HandleAuthenticateAsync_MismatchJktToken_ExpectFailure()
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
    public async Task HandleAuthenticateAsync_ValidDPoPToken_ExpectClaimsPrincipal()
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
    public async Task HandleAuthenticateAsync_ValidBearerToken_ExpectClaimsPrincipal()
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