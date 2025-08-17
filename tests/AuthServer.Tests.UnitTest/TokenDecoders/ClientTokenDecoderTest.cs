using System.Text.Json;
using AuthServer.Authentication.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Enums;
using AuthServer.Extensions;
using AuthServer.Tests.Core;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.TokenDecoders;

public class ClientTokenDecoderTest : BaseUnitTest
{
    public ClientTokenDecoderTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task Read_Jws_ExpectJsonWebToken()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();
        var token = JwtBuilder.GetPrivateKeyJwt(
            "client_id",
            ClientJwkBuilder.GetClientJwks().PrivateJwks,
            ClientTokenAudience.TokenEndpoint);

        // Act
        var jsonWebToken = await tokenDecoder.Read(token);

        // Assert
        Assert.NotNull(jsonWebToken);
    }

    [Fact]
    public async Task Read_Jwe_ExpectJsonWebToken()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();
        var token = JwtBuilder.GetEncryptedPrivateKeyJwt(
            "client_id",
            ClientJwkBuilder.GetClientJwks().PrivateJwks,
            ClientTokenAudience.TokenEndpoint);

        // Act
        var jsonWebToken = await tokenDecoder.Read(token);

        // Assert
        Assert.NotNull(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JwksWithoutHeader_ExpectNull()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(clientJwkService); });
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();

        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var privateJwks = new JsonWebKeySet(clientJwks.PrivateJwks);
        var publicJwks = new JsonWebKeySet(clientJwks.PublicJwks);
        const string clientId = "client_id";
        clientJwkService
            .Setup(x => x.GetSigningKeys(clientId, CancellationToken.None))
            .ReturnsAsync(publicJwks.Keys)
            .Verifiable();

        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(60),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = EndpointResolver.TokenEndpoint,
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = [signingKey.Alg],
                ClientId = clientId,
                Audience = ClientTokenAudience.TokenEndpoint,
                ValidateLifetime = true,
                UseJwkHeaderSignatureValidation = true
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JwsWithInvalidJwkHeader_ExpectNull()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(clientJwkService); });
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();

        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var privateJwks = new JsonWebKeySet(clientJwks.PrivateJwks);
        var publicJwks = new JsonWebKeySet(clientJwks.PublicJwks);
        const string clientId = "client_id";
        clientJwkService
            .Setup(x => x.GetSigningKeys(clientId, CancellationToken.None))
            .ReturnsAsync(publicJwks.Keys)
            .Verifiable();

        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(60),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = EndpointResolver.TokenEndpoint,
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                { ClaimNameConstants.Jwk, "invalid_jwk" }
            }
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = [signingKey.Alg],
                ClientId = clientId,
                Audience = ClientTokenAudience.TokenEndpoint,
                ValidateLifetime = true,
                UseJwkHeaderSignatureValidation = true
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JwsWithPrivateJwkHeader_ExpectNull()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(clientJwkService); });
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();

        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var privateJwks = new JsonWebKeySet(clientJwks.PrivateJwks);
        var publicJwks = new JsonWebKeySet(clientJwks.PublicJwks);
        const string clientId = "client_id";
        clientJwkService
            .Setup(x => x.GetSigningKeys(clientId, CancellationToken.None))
            .ReturnsAsync(publicJwks.Keys)
            .Verifiable();

        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(60),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = EndpointResolver.TokenEndpoint,
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                { ClaimNameConstants.Jwk, JsonSerializer.Serialize(signingKey) }
            }
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = [signingKey.Alg],
                ClientId = clientId,
                Audience = ClientTokenAudience.TokenEndpoint,
                ValidateLifetime = true,
                UseJwkHeaderSignatureValidation = true
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JwsWithExpiresAtExceeded_ExpectNull()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(clientJwkService); });
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();

        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var privateJwks = new JsonWebKeySet(clientJwks.PrivateJwks);
        var publicJwks = new JsonWebKeySet(clientJwks.PublicJwks);
        const string clientId = "client_id";
        clientJwkService
            .Setup(x => x.GetSigningKeys(clientId, CancellationToken.None))
            .ReturnsAsync(publicJwks.Keys)
            .Verifiable();

        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(-1),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = EndpointResolver.TokenEndpoint,
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = [signingKey.Alg],
                ClientId = clientId,
                Audience = ClientTokenAudience.TokenEndpoint,
                ValidateLifetime = true,
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JwsWithNotBeforeInTheFuture_ExpectNull()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(clientJwkService); });
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();

        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var privateJwks = new JsonWebKeySet(clientJwks.PrivateJwks);
        var publicJwks = new JsonWebKeySet(clientJwks.PublicJwks);
        const string clientId = "client_id";
        clientJwkService
            .Setup(x => x.GetSigningKeys(clientId, CancellationToken.None))
            .ReturnsAsync(publicJwks.Keys)
            .Verifiable();

        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            NotBefore = now.AddSeconds(30),
            Expires = now.AddSeconds(60),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = EndpointResolver.TokenEndpoint,
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = [signingKey.Alg],
                ClientId = clientId,
                Audience = ClientTokenAudience.TokenEndpoint,
                ValidateLifetime = true,
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JwsWithIssuedAtInTheFuture_ExpectNull()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(clientJwkService); });
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();

        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var privateJwks = new JsonWebKeySet(clientJwks.PrivateJwks);
        var publicJwks = new JsonWebKeySet(clientJwks.PublicJwks);
        const string clientId = "client_id";
        clientJwkService
            .Setup(x => x.GetSigningKeys(clientId, CancellationToken.None))
            .ReturnsAsync(publicJwks.Keys)
            .Verifiable();

        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(60),
            IssuedAt = now.AddSeconds(30),
            SigningCredentials = signingCredentials,
            Audience = EndpointResolver.TokenEndpoint,
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = [signingKey.Alg],
                ClientId = clientId,
                Audience = ClientTokenAudience.TokenEndpoint,
                ValidateLifetime = true,
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JwsWithInvalidTokenType_ExpectNull()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(clientJwkService); });
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();

        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var privateJwks = new JsonWebKeySet(clientJwks.PrivateJwks);
        var publicJwks = new JsonWebKeySet(clientJwks.PublicJwks);
        const string clientId = "client_id";
        clientJwkService
            .Setup(x => x.GetSigningKeys(clientId, CancellationToken.None))
            .ReturnsAsync(publicJwks.Keys)
            .Verifiable();

        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(60),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = EndpointResolver.TokenEndpoint,
            TokenType = "invalid_token_type"
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = [signingKey.Alg],
                ClientId = clientId,
                Audience = ClientTokenAudience.TokenEndpoint,
                ValidateLifetime = true,
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JwsWithInvalidIssuer_ExpectNull()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(clientJwkService); });
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();

        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var privateJwks = new JsonWebKeySet(clientJwks.PrivateJwks);
        var publicJwks = new JsonWebKeySet(clientJwks.PublicJwks);
        const string clientId = "client_id";
        clientJwkService
            .Setup(x => x.GetSigningKeys(clientId, CancellationToken.None))
            .ReturnsAsync(publicJwks.Keys)
            .Verifiable();

        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "invalid_issuer",
            NotBefore = now,
            Expires = now.AddSeconds(60),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = EndpointResolver.TokenEndpoint,
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = [signingKey.Alg],
                ClientId = clientId,
                Audience = ClientTokenAudience.TokenEndpoint,
                ValidateLifetime = true,
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JwsWithInvalidAudience_ExpectNull()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(clientJwkService); });
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();

        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var privateJwks = new JsonWebKeySet(clientJwks.PrivateJwks);
        var publicJwks = new JsonWebKeySet(clientJwks.PublicJwks);
        const string clientId = "client_id";
        clientJwkService
            .Setup(x => x.GetSigningKeys(clientId, CancellationToken.None))
            .ReturnsAsync(publicJwks.Keys)
            .Verifiable();

        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(60),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = "invalid_audience",
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = [signingKey.Alg],
                ClientId = clientId,
                Audience = ClientTokenAudience.TokenEndpoint,
                ValidateLifetime = true
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JwsWithInvalidAlgorithmForVerifyingSignature_ExpectNull()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services => { services.AddScopedMock(clientJwkService); });
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();

        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var privateJwks = new JsonWebKeySet(clientJwks.PrivateJwks);
        var publicJwks = new JsonWebKeySet(clientJwks.PublicJwks);
        const string clientId = "client_id";
        clientJwkService
            .Setup(x => x.GetSigningKeys(clientId, CancellationToken.None))
            .ReturnsAsync(publicJwks.Keys)
            .Verifiable();

        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(60),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = EndpointResolver.TokenEndpoint,
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = ["different-sig-algorithm"],
                ClientId = clientId,
                Audience = ClientTokenAudience.TokenEndpoint,
                ValidateLifetime = true,
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JweWithInvalidAlgorithmForDecryption_ExpectNull()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(clientJwkService);
        });
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();

        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var privateJwks = new JsonWebKeySet(clientJwks.PrivateJwks);
        var publicJwks = new JsonWebKeySet(clientJwks.PublicJwks);
        const string clientId = "client_id";
        clientJwkService
            .Setup(x => x.GetSigningKeys(clientId, CancellationToken.None))
            .ReturnsAsync(publicJwks.Keys)
            .Verifiable();

        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);

        var encryptingKey = JwksDocument.GetEncryptionKey(EncryptionAlg.RsaPKCS1);
        var encryptingCredentials = new EncryptingCredentials(encryptingKey, JweAlgConstants.RsaPKCS1, JweEncConstants.Aes128CbcHmacSha256);

        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object> { { Parameter.Subject, clientId } },
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(60),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            EncryptingCredentials = encryptingCredentials,
            Audience = EndpointResolver.TokenEndpoint,
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = [signingKey.Alg, "different-enc-algorithm"],
                ClientId = clientId,
                SubjectId = clientId,
                Audience = ClientTokenAudience.TokenEndpoint,
                ValidateLifetime = true,
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JwsWithInvalidSignature_ExpectNull()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(clientJwkService);
        });
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();

        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var publicJwks = new JsonWebKeySet(clientJwks.PublicJwks);
        const string clientId = "client_id";
        clientJwkService
            .Setup(x => x.GetSigningKeys(clientId, CancellationToken.None))
            .ReturnsAsync(publicJwks.Keys)
            .Verifiable();

        var signingKey = JwksDocument.GetSigningKey(SigningAlg.RsaSha256);
        var signingCredentials = new SigningCredentials(signingKey, SigningAlg.RsaSha256.GetDescription());
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(60),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = EndpointResolver.TokenEndpoint,
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = [SigningAlg.RsaSha256.GetDescription()],
                ClientId = clientId,
                Audience = ClientTokenAudience.TokenEndpoint,
                ValidateLifetime = true,
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
        clientJwkService.Verify();
    }

    [Fact]
    public async Task Validate_JweWithInvalidDecryption_ExpectNull()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(clientJwkService);
        });
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();

        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var privateJwks = new JsonWebKeySet(clientJwks.PrivateJwks);
        var publicJwks = new JsonWebKeySet(clientJwks.PublicJwks);
        const string clientId = "client_id";
        clientJwkService
            .Setup(x => x.GetSigningKeys(clientId, CancellationToken.None))
            .ReturnsAsync(publicJwks.Keys)
            .Verifiable();

        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);

        var encryptingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Enc);
        var encryptingCredentials = new EncryptingCredentials(encryptingKey, encryptingKey.Alg, JweEncConstants.Aes128CbcHmacSha256);

        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(60),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            EncryptingCredentials = encryptingCredentials,
            Audience = EndpointResolver.TokenEndpoint,
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = [signingKey.Alg],
                ClientId = clientId,
                Audience = ClientTokenAudience.TokenEndpoint,
                ValidateLifetime = true,
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JwsWithReplay_ExpectNull()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var tokenReplayCache = new Mock<ITokenReplayCache>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(clientJwkService);
            services.AddScopedMock(tokenReplayCache);
        });
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();

        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var privateJwks = new JsonWebKeySet(clientJwks.PrivateJwks);
        var publicJwks = new JsonWebKeySet(clientJwks.PublicJwks);
        const string clientId = "client_id";
        clientJwkService
            .Setup(x => x.GetSigningKeys(clientId, CancellationToken.None))
            .ReturnsAsync(publicJwks.Keys)
            .Verifiable();

        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(60),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = EndpointResolver.TokenEndpoint,
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken
        });

        tokenReplayCache
            .Setup(x => x.TryFind(clientJwt))
            .Returns(true);

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = [signingKey.Alg],
                ClientId = clientId,
                Audience = ClientTokenAudience.TokenEndpoint,
                ValidateLifetime = true,
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JwsWithInvalidSubject_ExpectNull()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(clientJwkService);
        });
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();

        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var privateJwks = new JsonWebKeySet(clientJwks.PrivateJwks);
        var publicJwks = new JsonWebKeySet(clientJwks.PublicJwks);
        const string clientId = "client_id";
        clientJwkService
            .Setup(x => x.GetSigningKeys(clientId, CancellationToken.None))
            .ReturnsAsync(publicJwks.Keys)
            .Verifiable();

        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>{ { Parameter.Subject, "invalid_subject" } },
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(60),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = EndpointResolver.TokenEndpoint,
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = [signingKey.Alg],
                ClientId = clientId,
                SubjectId = clientId,
                Audience = ClientTokenAudience.TokenEndpoint,
                ValidateLifetime = true,
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JweWithInvalidSubject_ExpectNull()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(clientJwkService);
        });
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();

        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var privateJwks = new JsonWebKeySet(clientJwks.PrivateJwks);
        var publicJwks = new JsonWebKeySet(clientJwks.PublicJwks);
        const string clientId = "client_id";
        clientJwkService
            .Setup(x => x.GetSigningKeys(clientId, CancellationToken.None))
            .ReturnsAsync(publicJwks.Keys)
            .Verifiable();

        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);

        var encryptingKey = JwksDocument.GetEncryptionKey(EncryptionAlg.RsaPKCS1);
        var encryptingCredentials = new EncryptingCredentials(encryptingKey, JweAlgConstants.RsaPKCS1, JweEncConstants.Aes128CbcHmacSha256);

        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object> { { Parameter.Subject, "invalid_subject" } },
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(60),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            EncryptingCredentials = encryptingCredentials,
            Audience = EndpointResolver.TokenEndpoint,
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = [signingKey.Alg, JweEncConstants.Aes128CbcHmacSha256],
                ClientId = clientId,
                SubjectId = clientId,
                Audience = ClientTokenAudience.TokenEndpoint,
                ValidateLifetime = true,
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JwsWithIssuedAtMoreThan60SecondsInThePast_ExpectNull()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(clientJwkService);
        });
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();

        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var privateJwks = new JsonWebKeySet(clientJwks.PrivateJwks);
        var publicJwks = new JsonWebKeySet(clientJwks.PublicJwks);
        const string clientId = "client_id";
        clientJwkService
            .Setup(x => x.GetSigningKeys(clientId, CancellationToken.None))
            .ReturnsAsync(publicJwks.Keys)
            .Verifiable();

        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object> { { Parameter.Subject, clientId } },
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(60),
            IssuedAt = now.AddSeconds(-120),
            SigningCredentials = signingCredentials,
            Audience = EndpointResolver.TokenEndpoint,
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = [signingKey.Alg],
                ClientId = clientId,
                SubjectId = clientId,
                Audience = ClientTokenAudience.TokenEndpoint,
                ValidateLifetime = true,
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JwsWithNotBeforeMoreThan60SecondsInThePast_ExpectNull()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(clientJwkService);
        });
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();

        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var privateJwks = new JsonWebKeySet(clientJwks.PrivateJwks);
        var publicJwks = new JsonWebKeySet(clientJwks.PublicJwks);
        const string clientId = "client_id";
        clientJwkService
            .Setup(x => x.GetSigningKeys(clientId, CancellationToken.None))
            .ReturnsAsync(publicJwks.Keys)
            .Verifiable();

        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object> { { Parameter.Subject, clientId } },
            Issuer = clientId,
            NotBefore = now.AddSeconds(-120),
            Expires = now.AddSeconds(60),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = EndpointResolver.TokenEndpoint,
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = [signingKey.Alg],
                ClientId = clientId,
                SubjectId = clientId,
                Audience = ClientTokenAudience.TokenEndpoint,
                ValidateLifetime = true,
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JwsWithExpiresAtMoreThan60SecondsInTheFuture_ExpectNull()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(clientJwkService);
        });
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();

        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var privateJwks = new JsonWebKeySet(clientJwks.PrivateJwks);
        var publicJwks = new JsonWebKeySet(clientJwks.PublicJwks);
        const string clientId = "client_id";
        clientJwkService
            .Setup(x => x.GetSigningKeys(clientId, CancellationToken.None))
            .ReturnsAsync(publicJwks.Keys)
            .Verifiable();

        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object> { { Parameter.Subject, clientId } },
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(120),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = EndpointResolver.TokenEndpoint,
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = [signingKey.Alg],
                ClientId = clientId,
                SubjectId = clientId,
                Audience = ClientTokenAudience.TokenEndpoint,
                ValidateLifetime = true,
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_Jws_ExpectJsonWebToken()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(clientJwkService);
        });
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();

        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var privateJwks = new JsonWebKeySet(clientJwks.PrivateJwks);
        var publicJwks = new JsonWebKeySet(clientJwks.PublicJwks);
        const string clientId = "client_id";
        clientJwkService
            .Setup(x => x.GetSigningKeys(clientId, CancellationToken.None))
            .ReturnsAsync(publicJwks.Keys)
            .Verifiable();

        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object> { { Parameter.Subject, clientId } },
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(60),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = EndpointResolver.TokenEndpoint,
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = [signingKey.Alg],
                ClientId = clientId,
                SubjectId = clientId,
                Audience = ClientTokenAudience.TokenEndpoint,
                ValidateLifetime = true,
            },
            CancellationToken.None);

        // Assert
        Assert.NotNull(jsonWebToken);
    }

    [Fact]
    public async Task Validate_Jwe_ExpectJsonWebToken()
    {
        // Arrange
        var clientJwkService = new Mock<IClientJwkService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(clientJwkService);
        });
        var tokenDecoder = serviceProvider.GetRequiredService<IClientTokenDecoder>();

        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var privateJwks = new JsonWebKeySet(clientJwks.PrivateJwks);
        var publicJwks = new JsonWebKeySet(clientJwks.PublicJwks);
        const string clientId = "client_id";
        clientJwkService
            .Setup(x => x.GetSigningKeys(clientId, CancellationToken.None))
            .ReturnsAsync(publicJwks.Keys)
            .Verifiable();

        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);

        var encryptingKey = JwksDocument.GetEncryptionKey(EncryptionAlg.RsaPKCS1);
        var encryptingCredentials = new EncryptingCredentials(encryptingKey, JweAlgConstants.RsaPKCS1, JweEncConstants.Aes128CbcHmacSha256);

        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object> { { Parameter.Subject, clientId } },
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(60),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            EncryptingCredentials = encryptingCredentials,
            Audience = EndpointResolver.TokenEndpoint,
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ClientTokenDecodeArguments
            {
                TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
                Algorithms = [signingKey.Alg, JweEncConstants.Aes128CbcHmacSha256],
                ClientId = clientId,
                SubjectId = clientId,
                Audience = ClientTokenAudience.TokenEndpoint,
                ValidateLifetime = true,
            },
            CancellationToken.None);

        // Assert
        Assert.NotNull(jsonWebToken);
    }
}