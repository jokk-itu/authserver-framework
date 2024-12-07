using System.Reflection;
using AuthServer.Authentication.Abstractions;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Extensions;
using AuthServer.Register;
using AuthServer.Repositories.Abstractions;
using AuthServer.RequestAccessors.Register;
using AuthServer.Tests.Core;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Register;

public class RegisterRequestValidatorTest : BaseUnitTest
{
    public RegisterRequestValidatorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    public async Task Validate_ClientIdIsNull_ExpectInvalidClientId(string httpMethod)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator =
            serviceProvider.GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Parse(httpMethod)
        };

        // Act
        var processError = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidClientId, processError);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    public async Task Validate_RegistrationAccessTokenIsNull_ExpectInvalidRegistrationAccessToken(string httpMethod)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator =
            serviceProvider.GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Parse(httpMethod),
            ClientId = "clientId"
        };

        // Act
        var processError = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidRegistrationAccessToken, processError);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    public async Task Validate_GivenRegistrationAccessTokenIsInactive_ExpectInvalidRegistrationAccessToken(string httpMethod)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator =
            serviceProvider.GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Parse(httpMethod),
            ClientId = "clientId",
            RegistrationAccessToken = "inactiveToken"
        };

        // Act
        var processError = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidRegistrationAccessToken, processError);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    public async Task Validate_ClientIdDoesNotMatchToken_ExpectMismatchingClientId(string httpMethod)
    {
        // Arrange
        var tokenRepository = new Mock<ITokenRepository>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(tokenRepository);
        });
        var validator =
            serviceProvider.GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var registrationToken = new RegistrationToken(client, "aud", "iss", ScopeConstants.Register);
        await AddEntity(registrationToken);

        var request = new RegisterRequest
        {
            Method = HttpMethod.Parse(httpMethod),
            ClientId = "clientId",
            RegistrationAccessToken = registrationToken.Reference
        };

        tokenRepository
            .Setup(x => x.GetActiveRegistrationToken(request.RegistrationAccessToken, CancellationToken.None))
            .ReturnsAsync(registrationToken)
            .Verifiable();

        // Act
        var processError = await validator.Validate(request, CancellationToken.None);

        // Assert
        tokenRepository.Verify();
        Assert.Equal(RegisterError.MismatchingClientId, processError);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("DELETE")]
    public async Task Validate_ValidRequestForDeleteAndGet_ExpectRegisterValidatedRequest(string httpMethod)
    {
        // Arrange
        var tokenRepository = new Mock<ITokenRepository>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(tokenRepository);
        });
        var validator =
            serviceProvider.GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var registrationToken = new RegistrationToken(client, "aud", "iss", ScopeConstants.Register);
        await AddEntity(registrationToken);

        var request = new RegisterRequest
        {
            Method = HttpMethod.Parse(httpMethod),
            ClientId = client.Id,
            RegistrationAccessToken = registrationToken.Reference
        };

        tokenRepository
            .Setup(x => x.GetActiveRegistrationToken(request.RegistrationAccessToken, CancellationToken.None))
            .ReturnsAsync(registrationToken)
            .Verifiable();

        // Act
        var processError = await validator.Validate(request, CancellationToken.None);

        // Assert
        tokenRepository.Verify();
        Assert.Equal(request.Method, processError.Value!.Method);
        Assert.Equal(request.ClientId, processError.Value!.ClientId);
        Assert.Equal(request.RegistrationAccessToken, processError.Value!.RegistrationAccessToken);
    }

    [Fact]
    public async Task Validate_InvalidApplicationType_ExpectInvalidApplicationType()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ApplicationType = "invalid_application_type"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidApplicationType, processResult);
    }

    [Fact]
    public async Task Validate_InvalidTokenEndpointAuthMethod_ExpectInvalidTokenEndpointAuthMethod()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            TokenEndpointAuthMethod = "invalid_token_endpoint_auth_method"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidTokenEndpointAuthMethod, processResult);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("duplicate")]
    public async Task Validate_InvalidClientName_ExpectInvalidClientName(string? clientName)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var client = new Client("duplicate", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        await AddEntity(client);

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = clientName
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidClientName, processResult);
    }

    [Fact]
    public async Task Validate_InvalidGrantTypes_ExpectInvalidGrantTypes()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            GrantTypes = ["invalid_grant_type"]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidGrantTypes, processResult);
    }

    [Fact]
    public async Task Validate_OnlyRefreshTokenGrantType_ExpectInvalidGrantType()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            GrantTypes = [GrantTypeConstants.RefreshToken]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidGrantTypes, processResult);
    }

    [Fact]
    public async Task Validate_InvalidScope_ExpectInvalidScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            Scope = ["invalid_scope"]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidScope, processResult);
    }

    [Fact]
    public async Task Validate_InvalidResponseType_ExpectInvalidResponseTypes()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            ResponseTypes = ["invalid_response_type"]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidResponseTypes, processResult);
    }

    [Fact]
    public async Task Validate_EmptyRedirectUris_ExpectInvalidRedirectUris()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["invalid_redirect_uris"]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidRedirectUris, processResult);
    }

    [Theory]
    [InlineData(ApplicationType.Web)]
    [InlineData(ApplicationType.Native)]
    public async Task Validate_InvalidRedirectUris_ExpectInvalidRedirectUris(ApplicationType applicationType)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            ApplicationType = applicationType.GetDescription(),
            RedirectUris = ["invalid_redirect_uri"]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidRedirectUris, processResult);
    }

    [Theory]
    [InlineData(ApplicationType.Web)]
    [InlineData(ApplicationType.Native)]
    public async Task Validate_InvalidPostLogoutRedirectUris_ExpectPostLogoutRedirectUris(ApplicationType applicationType)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            ApplicationType = applicationType.GetDescription(),
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            PostLogoutRedirectUris = ["invalid_post_logout_redirect_uri"]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidPostLogoutRedirectUris, processResult);
    }

    [Fact]
    public async Task Validate_InvalidRequestUris_ExpectRequestUris()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            ApplicationType = ApplicationType.Web.GetDescription(),
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            RequestUris = ["invalid_request_uri"]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidRequestUris, processResult);
    }

    [Fact]
    public async Task Validate_NoSectorIdentifierUriAndMultipleRedirectUris_InvalidSectorIdentifier()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback", "https://webapp.authserver.dk/callback2"],
            SubjectType = SubjectType.Pairwise.GetDescription()
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidSectorIdentifierUri, processResult);
    }

    [Fact]
    public async Task Validate_InvalidSectorIdentifierUri_InvalidSectorIdentifier()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            SubjectType = SubjectType.Pairwise.GetDescription(),
            SectorIdentifierUri = "invalid_sector_identifier_uri"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidSectorIdentifierUri, processResult);
    }

    [Fact]
    public async Task Validate_NoRedirectUriInSectorDocument_ExpectInvalidSectorDocument()
    {
        // Arrange
        var clientSectorService = new Mock<IClientSectorService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(clientSectorService);
        });
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            SubjectType = SubjectType.Pairwise.GetDescription(),
            SectorIdentifierUri = "https://webapp.authserver.dk/sector"
        };

        clientSectorService
            .Setup(x => x.ContainsSectorDocument(
                It.Is<Uri>(y => y.ToString() == request.SectorIdentifierUri),
                request.RedirectUris,
                CancellationToken.None))
            .ReturnsAsync(false)
            .Verifiable();

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidSectorDocument, processResult);
    }

    [Fact]
    public async Task Validate_InvalidBackchannelLogoutUri_ExpectInvalidBackchannelLogoutUri()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            BackchannelLogoutUri = "invalid_backchannel_logout_uri"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidBackchannelLogoutUri, processResult);
    }

    [Fact]
    public async Task Validate_InvalidClientUri_ExpectInvalidClientUri()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            ClientUri = "invalid_client_uri"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidClientUri, processResult);
    }

    [Fact]
    public async Task Validate_InvalidPolicyUri_ExpectInvalidPolicyUri()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            PolicyUri = "invalid_policy_uri"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidPolicyUri, processResult);
    }

    [Fact]
    public async Task Validate_InvalidTosUri_ExpectInvalidTosUri()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            TosUri = "invalid_tos_uri"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidTosUri, processResult);
    }

    [Fact]
    public async Task Validate_InvalidInitiateLoginUri_ExpectInvalidInitiateLoginUri()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            InitiateLoginUri = "invalid_initiate_login_uri"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidInitiateLoginUri, processResult);
    }

    [Fact]
    public async Task Validate_InvalidLogoUri_ExpectInvalidLogoUri()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            LogoUri = "invalid_logo_uri"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidLogoUri, processResult);
    }

    [Fact]
    public async Task Validate_GiveJwksAndJwksUri_ExpectInvalidJwksAndJwksUri()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            Jwks = "jwks",
            JwksUri = "jwks_uri"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidJwksAndJwksUri, processResult);
    }

    [Fact]
    public async Task Validate_NoJwksOrJwksUriAndPrivateKeyJwtAuthMethod_ExpectInvalidJwksOrJwksUri()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            TokenEndpointAuthMethod = TokenEndpointAuthMethod.PrivateKeyJwt.GetDescription()
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidJwksOrJwksUri, processResult);
    }

    [Fact]
    public async Task Validate_InvalidJwks_ExpectInvalidJwks()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            Jwks = "invalid_jwks"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidJwks, processResult);
    }

    [Fact]
    public async Task Validate_InvalidJwksUri_ExpectInvalidJwksUri()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(clientJwkService);
        });
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            SubjectType = SubjectType.Pairwise.GetDescription(),
            JwksUri = "https://webapp.authserver.dk/jwks"
        };

        clientJwkService
            .Setup(x => x.GetJwks(request.JwksUri, CancellationToken.None))
            .ReturnsAsync((string?)null)
            .Verifiable();

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidJwksUri, processResult);
        clientJwkService.Verify();
    }

    [Fact]
    public async Task Validate_InvalidJwksFromJwksUri_ExpectInvalidJwksUri()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(clientJwkService);
        });
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            SubjectType = SubjectType.Pairwise.GetDescription(),
            JwksUri = "https://webapp.authserver.dk/jwks"
        };

        clientJwkService
            .Setup(x => x.GetJwks(request.JwksUri, CancellationToken.None))
            .ReturnsAsync("invalid_jwks")
            .Verifiable();

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidJwksUri, processResult);
        clientJwkService.Verify();
    }

    [Fact]
    public async Task Validate_InvalidDefaultMaxAge_ExpectInvalidDefaultMaxAge()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            DefaultMaxAge = "invalid_number"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidDefaultMaxAge, processResult);
    }

    [Fact]
    public async Task Validate_InvalidDefaultAcrValues_ExpectInvalidDefaultAcrValues()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            DefaultAcrValues = ["invalid_acr"]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidDefaultAcrValues, processResult);
    }

    [Fact]
    public async Task Validate_InvalidContacts_ExpectInvalidContacts()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            Contacts = ["invalid_contact"]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidContacts, processResult);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(601)]
    public async Task Validate_InvalidAuthorizationCodeExpiration_ExpectInvalidAuthorizationCodeExpiration(int expiration)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            AuthorizationCodeExpiration = expiration
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidAuthorizationCodeExpiration, processResult);
    }

    [Theory]
    [InlineData(59)]
    [InlineData(3601)]
    public async Task Validate_InvalidAccessTokenExpiration_ExpectInvalidAccessTokenExpiration(int expiration)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            AccessTokenExpiration = expiration
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidAccessTokenExpiration, processResult);
    }

    [Theory]
    [InlineData(59)]
    [InlineData(5184001)]
    public async Task Validate_InvalidRefreshTokenExpiration_ExpectInvalidRefreshTokenExpiration(int expiration)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            RefreshTokenExpiration = expiration
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidRefreshTokenExpiration, processResult);
    }

    [Fact]
    public async Task Validate_InvalidClientSecretExpiration_ExpectInvalidClientSecretExpiration()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
             ClientSecretExpiration = 86399
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidClientSecretExpiration, processResult);
    }

    [Fact]
    public async Task Validate_InvalidJwksExpiration_ExpectInvalidJwksExpiration()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            JwksExpiration = -1
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidJwksExpiration, processResult);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(601)]
    public async Task Validate_InvalidRequestUriExpiration_ExpectInvalidRequestUriExpiration(int expiration)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            RequestUriExpiration = expiration
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidRequestUriExpiration, processResult);
    }

    [Fact]
    public async Task Validate_InvalidTokenEndpointAuthSigningAlg_ExpectInvalidTokenEndpointAuthSigningAlg()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            TokenEndpointAuthSigningAlg = "invalid_token_endpoint_auth_signing_alg"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidTokenEndpointAuthSigningAlg, processResult);
    }

    [Fact]
    public async Task Validate_InvalidRequestObjectSigningAlg_ExpectInvalidRequestObjectSigningAlg()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            RequestObjectSigningAlg = "invalid_request_object_signing_alg"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidRequestObjectSigningAlg, processResult);
    }

    [Fact]
    public async Task Validate_EmptyRequestObjectEncryptionAlgAndGivenRequestObjectEncryptionEnc_ExpectInvalidRequestObjectEncryptionEnc()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            RequestObjectSigningAlg = SigningAlg.RsaSha256.GetDescription(),
            RequestObjectEncryptionEnc = EncryptionEnc.Aes128CbcHmacSha256.GetDescription()
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidRequestObjectEncryptionEnc, processResult);
    }

    [Fact]
    public async Task Validate_InvalidRequestObjectEncryptionAlg_ExpectRequestObjectEncryptionAlg()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            RequestObjectSigningAlg = SigningAlg.RsaSha256.GetDescription(),
            RequestObjectEncryptionAlg = "invalid_request_object_encryption_alg"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidRequestObjectEncryptionAlg, processResult);
    }

    [Fact]
    public async Task Validate_InvalidRequestObjectEncryptionEnc_ExpectInvalidRequestObjectEncryptionEnc()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            RequestObjectSigningAlg = SigningAlg.RsaSha256.GetDescription(),
            RequestObjectEncryptionAlg = EncryptionAlg.EcdhEsA128KW.GetDescription(),
            RequestObjectEncryptionEnc = "invalid_request_object_encryption_enc"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidRequestObjectEncryptionEnc, processResult);
    }

    [Fact]
    public async Task Validate_InvalidUserinfoSignedResponseAlg_ExpectInvalidUserinfoSignedResponseAlg()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            UserinfoSignedResponseAlg = "invalid_userinfo_signed_response_alg"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidUserinfoSignedResponseAlg, processResult);
    }

    [Fact]
    public async Task Validate_EmptyUserinfoEncryptedResponseAlgAndGivenUserinfoEncryptedResponseEnc_ExpectInvalidUserinfoEncryptedResponseEnc()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            UserinfoSignedResponseAlg = SigningAlg.RsaSha256.GetDescription(),
            UserinfoEncryptedResponseEnc = EncryptionEnc.Aes128CbcHmacSha256.GetDescription()
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidUserinfoEncryptedResponseEnc, processResult);
    }

    [Fact]
    public async Task Validate_InvalidUserinfoEncryptedResponseAlg_ExpectUserinfoEncryptedResponseAlg()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            UserinfoSignedResponseAlg = SigningAlg.RsaSha256.GetDescription(),
            UserinfoEncryptedResponseAlg = "invalid_userinfo_encrypted_response_alg"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidUserinfoEncryptedResponseAlg, processResult);
    }

    [Fact]
    public async Task Validate_InvalidUserinfoEncryptedResponseEnc_ExpectInvalidUserinfoEncryptedResponseEnc()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            UserinfoSignedResponseAlg = SigningAlg.RsaSha256.GetDescription(),
            UserinfoEncryptedResponseAlg = EncryptionAlg.EcdhEsA128KW.GetDescription(),
            UserinfoEncryptedResponseEnc = "invalid_userinfo_encrypted_response_enc"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidUserinfoEncryptedResponseEnc, processResult);
    }

    [Fact]
    public async Task Validate_InvalidIdTokenSignedResponseAlg_ExpectInvalidIdTokenSignedResponseAlg()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            IdTokenSignedResponseAlg = "invalid_id_token_signed_response_alg"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidIdTokenSignedResponseAlg, processResult);
    }

    [Fact]
    public async Task Validate_EmptyIdTokenEncryptedResponseAlgAndGivenIdTokenEncryptedResponseEnc_ExpectInvalidIdTokenEncryptedResponseEnc()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            IdTokenSignedResponseAlg = SigningAlg.RsaSha256.GetDescription(),
            IdTokenEncryptedResponseEnc = EncryptionEnc.Aes128CbcHmacSha256.GetDescription()
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidIdTokenEncryptedResponseEnc, processResult);
    }

    [Fact]
    public async Task Validate_InvalidIdTokenEncryptedResponseAlg_ExpectIdTokenEncryptedResponseAlg()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            IdTokenSignedResponseAlg = SigningAlg.RsaSha256.GetDescription(),
            IdTokenEncryptedResponseAlg = "invalid_userinfo_encrypted_response_alg"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidIdTokenEncryptedResponseAlg, processResult);
    }

    [Fact]
    public async Task Validate_InvalidIdTokenEncryptedResponseEnc_ExpectInvalidIdTokenEncryptedResponseEnc()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<RegisterRequest, RegisterValidatedRequest>>();

        var request = new RegisterRequest
        {
            Method = HttpMethod.Post,
            ClientName = "web-app",
            RedirectUris = ["https://webapp.authserver.dk/callback"],
            IdTokenSignedResponseAlg = SigningAlg.RsaSha256.GetDescription(),
            IdTokenEncryptedResponseAlg = EncryptionAlg.EcdhEsA128KW.GetDescription(),
            IdTokenEncryptedResponseEnc = "invalid_userinfo_encrypted_response_enc"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(RegisterError.InvalidIdTokenEncryptedResponseEnc, processResult);
    }
}