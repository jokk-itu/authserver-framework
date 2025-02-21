using AuthServer.Tests.Core;
using AuthServer.TokenDecoders.Abstractions;
using AuthServer.TokenDecoders;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;
using AuthServer.Constants;
using AuthServer.Enums;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.Tests.UnitTest.TokenDecoders;

public class ServerIssuedTokenDecoderTest : BaseUnitTest
{
    public ServerIssuedTokenDecoderTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task Read_Jws_ExpectJsonWebToken()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<ITokenDecoder<ServerIssuedTokenDecodeArguments>>();
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
        var tokenDecoder = serviceProvider.GetRequiredService<ITokenDecoder<ServerIssuedTokenDecodeArguments>>();
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
    public async Task Validate_JwsWithLifetimeExceeded_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<ITokenDecoder<ServerIssuedTokenDecodeArguments>>();

        var signingKey = JwksDocument.GetSigningKey(SigningAlg.RsaSha256);
        var signingCredentials = new SigningCredentials(signingKey, JwsAlgConstants.RsaSha256);
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = DiscoveryDocument.Issuer,
            NotBefore = now,
            Expires = now.AddSeconds(-1),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = DiscoveryDocument.Issuer,
            TokenType = TokenTypeHeaderConstants.AccessToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ServerIssuedTokenDecodeArguments
            {
               ValidateLifetime = true,
               Audiences = [DiscoveryDocument.Issuer],
               TokenTypes = [TokenTypeHeaderConstants.AccessToken]
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JwsWithInvalidTokenType_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<ITokenDecoder<ServerIssuedTokenDecodeArguments>>();

        var signingKey = JwksDocument.GetSigningKey(SigningAlg.RsaSha256);
        var signingCredentials = new SigningCredentials(signingKey, JwsAlgConstants.RsaSha256);
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = DiscoveryDocument.Issuer,
            NotBefore = now,
            Expires = now.AddSeconds(300),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = DiscoveryDocument.Issuer,
            TokenType = "invalid_token_type"
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ServerIssuedTokenDecodeArguments
            {
                ValidateLifetime = true,
                Audiences = [DiscoveryDocument.Issuer],
                TokenTypes = [TokenTypeHeaderConstants.AccessToken]
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JwsWithInvalidIssuer_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<ITokenDecoder<ServerIssuedTokenDecodeArguments>>();

        var signingKey = JwksDocument.GetSigningKey(SigningAlg.RsaSha256);
        var signingCredentials = new SigningCredentials(signingKey, JwsAlgConstants.RsaSha256);
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = "invalid_issuer",
            NotBefore = now,
            Expires = now.AddSeconds(300),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = DiscoveryDocument.Issuer,
            TokenType = TokenTypeHeaderConstants.AccessToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ServerIssuedTokenDecodeArguments
            {
                ValidateLifetime = true,
                Audiences = [DiscoveryDocument.Issuer],
                TokenTypes = [TokenTypeHeaderConstants.AccessToken]
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JwsWithInvalidAudience_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<ITokenDecoder<ServerIssuedTokenDecodeArguments>>();

        var signingKey = JwksDocument.GetSigningKey(SigningAlg.RsaSha256);
        var signingCredentials = new SigningCredentials(signingKey, JwsAlgConstants.RsaSha256);
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = DiscoveryDocument.Issuer,
            NotBefore = now,
            Expires = now.AddSeconds(300),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = "invalid_audience",
            TokenType = TokenTypeHeaderConstants.AccessToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ServerIssuedTokenDecodeArguments
            {
                ValidateLifetime = true,
                Audiences = [DiscoveryDocument.Issuer],
                TokenTypes = [TokenTypeHeaderConstants.AccessToken]
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JwsWithInvalidSignature_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<ITokenDecoder<ServerIssuedTokenDecodeArguments>>();

        var privateJwks = JsonWebKeySet.Create(ClientJwkBuilder.GetClientJwks().PrivateJwks);
        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);
        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = DiscoveryDocument.Issuer,
            NotBefore = now,
            Expires = now.AddSeconds(300),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = DiscoveryDocument.Issuer,
            TokenType = TokenTypeHeaderConstants.AccessToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ServerIssuedTokenDecodeArguments
            {
                ValidateLifetime = true,
                Audiences = [DiscoveryDocument.Issuer],
                TokenTypes = [TokenTypeHeaderConstants.AccessToken]
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_JwsWithInvalidDecryption_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<ITokenDecoder<ServerIssuedTokenDecodeArguments>>();

        var signingKey = JwksDocument.GetSigningKey(SigningAlg.RsaSha256);
        var signingCredentials = new SigningCredentials(signingKey, JwsAlgConstants.RsaSha256);

        var privateJwks = JsonWebKeySet.Create(ClientJwkBuilder.GetClientJwks().PrivateJwks);
        var encryptingKey = privateJwks.Keys.First(x => x.Use == JsonWebKeyUseNames.Sig);
        var encryptingCredentials = new EncryptingCredentials(encryptingKey, JweAlgConstants.RsaPKCS1, JweEncConstants.Aes128CbcHmacSha256);

        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = DiscoveryDocument.Issuer,
            NotBefore = now,
            Expires = now.AddSeconds(300),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            EncryptingCredentials = encryptingCredentials,
            Audience = DiscoveryDocument.Issuer,
            TokenType = TokenTypeHeaderConstants.AccessToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ServerIssuedTokenDecodeArguments
            {
                ValidateLifetime = true,
                Audiences = [DiscoveryDocument.Issuer],
                TokenTypes = [TokenTypeHeaderConstants.AccessToken]
            },
            CancellationToken.None);

        // Assert
        Assert.Null(jsonWebToken);
    }

    [Fact]
    public async Task Validate_Jws_ExpectJsonWebToken()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<ITokenDecoder<ServerIssuedTokenDecodeArguments>>();

        var signingKey = JwksDocument.GetSigningKey(SigningAlg.RsaSha256);
        var signingCredentials = new SigningCredentials(signingKey, JwsAlgConstants.RsaSha256);

        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = DiscoveryDocument.Issuer,
            NotBefore = now,
            Expires = now.AddSeconds(300),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = DiscoveryDocument.Issuer,
            TokenType = TokenTypeHeaderConstants.AccessToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ServerIssuedTokenDecodeArguments
            {
                ValidateLifetime = true,
                Audiences = [DiscoveryDocument.Issuer],
                TokenTypes = [TokenTypeHeaderConstants.AccessToken]
            },
            CancellationToken.None);

        // Assert
        Assert.NotNull(jsonWebToken);
    }

    [Fact]
    public async Task Validate_Jwe_ExpectJsonWebToken()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<ITokenDecoder<ServerIssuedTokenDecodeArguments>>();

        var signingKey = JwksDocument.GetSigningKey(SigningAlg.RsaSha256);
        var signingCredentials = new SigningCredentials(signingKey, JwsAlgConstants.RsaSha256);

        var encryptingKey = JwksDocument.GetEncryptionKey(EncryptionAlg.RsaPKCS1);
        var encryptingCredentials = new EncryptingCredentials(encryptingKey, JweAlgConstants.RsaPKCS1, JweEncConstants.Aes128CbcHmacSha256);

        var now = DateTime.UtcNow;
        var clientJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = DiscoveryDocument.Issuer,
            NotBefore = now,
            Expires = now.AddSeconds(300),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            EncryptingCredentials = encryptingCredentials,
            Audience = DiscoveryDocument.Issuer,
            TokenType = TokenTypeHeaderConstants.AccessToken
        });

        // Act
        var jsonWebToken = await tokenDecoder.Validate(
            clientJwt,
            new ServerIssuedTokenDecodeArguments
            {
                ValidateLifetime = true,
                Audiences = [DiscoveryDocument.Issuer],
                TokenTypes = [TokenTypeHeaderConstants.AccessToken]
            },
            CancellationToken.None);

        // Assert
        Assert.NotNull(jsonWebToken);
    }
}