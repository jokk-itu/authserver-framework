using AuthServer.Constants;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Tests.Core;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.TokenDecoders;

public class ServerTokenDecoderTest : BaseUnitTest
{
    public ServerTokenDecoderTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task Read_Jws_ExpectTokenResult()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<IServerTokenDecoder>();

        var signingKey = JwksDocument.GetSigningKey(SigningAlg.RsaSha256);
        var signingCredentials = new SigningCredentials(signingKey, JwsAlgConstants.RsaSha256);

        var now = DateTime.UtcNow;
        var jwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = DiscoveryDocument.Issuer,
            NotBefore = now,
            Expires = now.AddSeconds(300),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = DiscoveryDocument.Issuer,
            TokenType = TokenTypeHeaderConstants.AccessToken,
            Claims = new Dictionary<string, object>
            {
                { ClaimNameConstants.ClientId, "client_id" },
                { ClaimNameConstants.Jti, Guid.NewGuid() },
                { ClaimNameConstants.Sub, Guid.NewGuid() },
                { ClaimNameConstants.Scope, ScopeConstants.OpenId },
            }
        });

        // Act
        var tokenResult = await tokenDecoder.Read(jwt, CancellationToken.None);

        // Assert
        Assert.NotNull(tokenResult);
    }

    [Fact]
    public async Task Read_Jwe_ExpectTokenResult()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<IServerTokenDecoder>();

        var signingKey = JwksDocument.GetSigningKey(SigningAlg.RsaSha256);
        var signingCredentials = new SigningCredentials(signingKey, JwsAlgConstants.RsaSha256);

        var encryptingKey = JwksDocument.GetEncryptionKey(EncryptionAlg.RsaPKCS1);
        var encryptingCredentials = new EncryptingCredentials(encryptingKey, JweAlgConstants.RsaPKCS1, JweEncConstants.Aes128CbcHmacSha256);

        var now = DateTime.UtcNow;
        var jwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = DiscoveryDocument.Issuer,
            NotBefore = now,
            Expires = now.AddSeconds(300),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            EncryptingCredentials = encryptingCredentials,
            Audience = DiscoveryDocument.Issuer,
            TokenType = TokenTypeHeaderConstants.AccessToken,
            Claims = new Dictionary<string, object>
            {
                { ClaimNameConstants.ClientId, "client_id" },
                { ClaimNameConstants.Jti, Guid.NewGuid() },
                { ClaimNameConstants.Sub, Guid.NewGuid() },
                { ClaimNameConstants.Scope, ScopeConstants.OpenId },
            }
        });

        // Act
        var tokenResult = await tokenDecoder.Read(jwt, CancellationToken.None);

        // Assert
        Assert.NotNull(tokenResult);
    }

    [Fact]
    public async Task Read_ReferenceToken_ExpectTokenResult()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<IServerTokenDecoder>();

        var client = new Client("app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var accessToken = new ClientAccessToken(client, "resource1", DiscoveryDocument.Issuer, ScopeConstants.OpenId, client.AccessTokenExpiration);
        await AddEntity(accessToken);

        // Act
        var tokenResult = await tokenDecoder.Read(accessToken.Reference, CancellationToken.None);

        // Assert
        Assert.NotNull(tokenResult);
        Assert.Equal(client.Id, tokenResult.ClientId);
        Assert.Equal(accessToken.Id.ToString(), tokenResult.Jti);
        Assert.Equal(client.Id, tokenResult.Sub);
        Assert.Equal(TokenTypeHeaderConstants.AccessToken, tokenResult.Typ);
        Assert.Equal(accessToken.Scope!.Split(' '), tokenResult.Scope);
        Assert.Null(tokenResult.GrantId);
        Assert.Null(tokenResult.Jkt);
        Assert.Null(tokenResult.Sid);
    }

    [Fact]
    public async Task Validate_JwsWithLifetimeExceeded_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<IServerTokenDecoder>();

        var signingKey = JwksDocument.GetSigningKey(SigningAlg.RsaSha256);
        var signingCredentials = new SigningCredentials(signingKey, JwsAlgConstants.RsaSha256);
        var now = DateTime.UtcNow;
        var jwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
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
            jwt,
            new ServerTokenDecodeArguments
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
    public async Task Validate_ReferenceTokenWithLifetimeExceeded_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<IServerTokenDecoder>();

        var client = new Client("app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var accessToken = new ClientAccessToken(client, "resource1", DiscoveryDocument.Issuer, ScopeConstants.OpenId, -30);
        await AddEntity(accessToken);

        // Act
        var tokenResult = await tokenDecoder.Validate(
            accessToken.Reference,
            new ServerTokenDecodeArguments
            {
                ValidateLifetime = true,
                Audiences = [accessToken.Audience],
                TokenTypes = [TokenTypeHeaderConstants.AccessToken]
            },
            CancellationToken.None);

        // Assert
        Assert.Null(tokenResult);
    }

    [Fact]
    public async Task Validate_JwsWithInvalidTokenType_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<IServerTokenDecoder>();

        var signingKey = JwksDocument.GetSigningKey(SigningAlg.RsaSha256);
        var signingCredentials = new SigningCredentials(signingKey, JwsAlgConstants.RsaSha256);
        var now = DateTime.UtcNow;
        var jwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
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
            jwt,
            new ServerTokenDecodeArguments
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
    public async Task Validate_ReferenceTokenWithInvalidTokenType_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<IServerTokenDecoder>();

        var client = new Client("app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var accessToken = new ClientAccessToken(client, "resource1", DiscoveryDocument.Issuer, ScopeConstants.OpenId, client.AccessTokenExpiration);
        await AddEntity(accessToken);

        // Act
        var tokenResult = await tokenDecoder.Validate(
            accessToken.Reference,
            new ServerTokenDecodeArguments
            {
                ValidateLifetime = true,
                Audiences = [accessToken.Audience],
                TokenTypes = [TokenTypeHeaderConstants.RefreshToken]
            },
            CancellationToken.None);

        // Assert
        Assert.Null(tokenResult);
    }

    [Fact]
    public async Task Validate_JwsWithInvalidIssuer_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<IServerTokenDecoder>();

        var signingKey = JwksDocument.GetSigningKey(SigningAlg.RsaSha256);
        var signingCredentials = new SigningCredentials(signingKey, JwsAlgConstants.RsaSha256);
        var now = DateTime.UtcNow;
        var jwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
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
            jwt,
            new ServerTokenDecodeArguments
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
        var tokenDecoder = serviceProvider.GetRequiredService<IServerTokenDecoder>();

        var signingKey = JwksDocument.GetSigningKey(SigningAlg.RsaSha256);
        var signingCredentials = new SigningCredentials(signingKey, JwsAlgConstants.RsaSha256);
        var now = DateTime.UtcNow;
        var jwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
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
            jwt,
            new ServerTokenDecodeArguments
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
    public async Task Validate_ReferenceTokenWithInvalidAudience_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<IServerTokenDecoder>();

        var client = new Client("app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var accessToken = new ClientAccessToken(client, "resource1", DiscoveryDocument.Issuer, ScopeConstants.OpenId, client.AccessTokenExpiration);
        await AddEntity(accessToken);

        // Act
        var tokenResult = await tokenDecoder.Validate(
            accessToken.Reference,
            new ServerTokenDecodeArguments
            {
                ValidateLifetime = true,
                Audiences = ["resource2"],
                TokenTypes = [TokenTypeHeaderConstants.AccessToken]
            },
            CancellationToken.None);

        // Assert
        Assert.Null(tokenResult);
    }

    [Fact]
    public async Task Validate_JwsWithInvalidSignature_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<IServerTokenDecoder>();

        var privateJwks = JsonWebKeySet.Create(ClientJwkBuilder.GetClientJwks().PrivateJwks);
        var signingKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(signingKey, signingKey.Alg);
        var now = DateTime.UtcNow;
        var jwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
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
            jwt,
            new ServerTokenDecodeArguments
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
        var tokenDecoder = serviceProvider.GetRequiredService<IServerTokenDecoder>();

        var signingKey = JwksDocument.GetSigningKey(SigningAlg.RsaSha256);
        var signingCredentials = new SigningCredentials(signingKey, JwsAlgConstants.RsaSha256);

        var privateJwks = JsonWebKeySet.Create(ClientJwkBuilder.GetClientJwks().PrivateJwks);
        var encryptingKey = privateJwks.Keys.First(x => x.Use == JsonWebKeyUseNames.Sig);
        var encryptingCredentials = new EncryptingCredentials(encryptingKey, JweAlgConstants.RsaPKCS1, JweEncConstants.Aes128CbcHmacSha256);

        var now = DateTime.UtcNow;
        var jwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
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
            jwt,
            new ServerTokenDecodeArguments
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
    public async Task Validate_JwsDPoPBoundClientAccessToken_ExpectTokenResult()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<IServerTokenDecoder>();

        var signingKey = JwksDocument.GetSigningKey(SigningAlg.RsaSha256);
        var signingCredentials = new SigningCredentials(signingKey, JwsAlgConstants.RsaSha256);

        var now = DateTime.UtcNow;
        var clientId = Guid.NewGuid().ToString();
        var jti = Guid.NewGuid().ToString();
        var subject = Guid.NewGuid().ToString();
        var scope = ScopeConstants.OpenId;
        var jkt = "jkt";
        var jwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = DiscoveryDocument.Issuer,
            NotBefore = now,
            Expires = now.AddSeconds(300),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = DiscoveryDocument.Issuer,
            TokenType = TokenTypeHeaderConstants.AccessToken,
            Claims = new Dictionary<string, object>
            {
                { ClaimNameConstants.ClientId, clientId },
                { ClaimNameConstants.Jti, jti },
                { ClaimNameConstants.Sub, subject },
                { ClaimNameConstants.Scope, scope },
                {
                    ClaimNameConstants.Cnf, new Dictionary<string, object>
                    {
                        { ClaimNameConstants.Jkt, jkt }
                    }
                }
            }
        });

        // Act
        var tokenResult = await tokenDecoder.Validate(
            jwt,
            new ServerTokenDecodeArguments
            {
                ValidateLifetime = true,
                Audiences = [DiscoveryDocument.Issuer],
                TokenTypes = [TokenTypeHeaderConstants.AccessToken]
            },
            CancellationToken.None);

        // Assert
        Assert.NotNull(tokenResult);
        Assert.Equal(clientId, tokenResult.ClientId);
        Assert.Equal(jti, tokenResult.Jti);
        Assert.Equal(subject, tokenResult.Sub);
        Assert.Equal(TokenTypeHeaderConstants.AccessToken, tokenResult.Typ);
        Assert.Equal(scope.Split(' '), tokenResult.Scope);
        Assert.Null(tokenResult.GrantId);
        Assert.Equal(jkt, tokenResult.Jkt);
        Assert.Null(tokenResult.Sid);
        Assert.Null(tokenResult.Act);
        Assert.Null(tokenResult.MayAct);
    }

    [Fact]
    public async Task Validate_JweGrantAccessToken_ExpectTokenResult()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<IServerTokenDecoder>();

        var signingKey = JwksDocument.GetSigningKey(SigningAlg.RsaSha256);
        var signingCredentials = new SigningCredentials(signingKey, JwsAlgConstants.RsaSha256);

        var encryptingKey = JwksDocument.GetEncryptionKey(EncryptionAlg.RsaPKCS1);
        var encryptingCredentials = new EncryptingCredentials(encryptingKey, JweAlgConstants.RsaPKCS1, JweEncConstants.Aes128CbcHmacSha256);

        var now = DateTime.UtcNow;
        var clientId = Guid.NewGuid().ToString();
        var jti = Guid.NewGuid().ToString();
        var subject = Guid.NewGuid().ToString();
        var scope = ScopeConstants.OpenId;
        var grantId = Guid.NewGuid().ToString();
        var sid = Guid.NewGuid().ToString();
        var act = Guid.NewGuid().ToString();
        var mayAct = Guid.NewGuid().ToString();
        var jwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = DiscoveryDocument.Issuer,
            NotBefore = now,
            Expires = now.AddSeconds(300),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            EncryptingCredentials = encryptingCredentials,
            Audience = DiscoveryDocument.Issuer,
            TokenType = TokenTypeHeaderConstants.AccessToken,
            Claims = new Dictionary<string, object>
            {
                { ClaimNameConstants.ClientId, clientId },
                { ClaimNameConstants.Jti, jti },
                { ClaimNameConstants.Sub, subject },
                { ClaimNameConstants.Scope, scope },
                { ClaimNameConstants.GrantId, grantId },
                { ClaimNameConstants.Sid, sid },
                {
                    ClaimNameConstants.Act, new Dictionary<string, object>
                    {
                        { ClaimNameConstants.Sub, act }
                    }
                },
                {
                    ClaimNameConstants.MayAct, new Dictionary<string, object>
                    {
                        { ClaimNameConstants.Sub, mayAct }
                    }
                }
            }
        });

        // Act
        var tokenResult = await tokenDecoder.Validate(
            jwt,
            new ServerTokenDecodeArguments
            {
                ValidateLifetime = true,
                Audiences = [DiscoveryDocument.Issuer],
                TokenTypes = [TokenTypeHeaderConstants.AccessToken]
            },
            CancellationToken.None);

        // Assert
        Assert.NotNull(tokenResult);
        Assert.Equal(clientId, tokenResult.ClientId);
        Assert.Equal(jti, tokenResult.Jti);
        Assert.Equal(subject, tokenResult.Sub);
        Assert.Equal(TokenTypeHeaderConstants.AccessToken, tokenResult.Typ);
        Assert.Equal(scope.Split(' '), tokenResult.Scope);
        Assert.Equal(grantId, tokenResult.GrantId);
        Assert.Null(tokenResult.Jkt);
        Assert.Equal(sid, tokenResult.Sid);
        Assert.NotNull(tokenResult.Act);
        Assert.Equal(act, tokenResult.Act.Sub);
        Assert.NotNull(tokenResult.MayAct);
        Assert.Equal(mayAct, tokenResult.MayAct.Sub);
    }

    [Theory]
    [InlineData(true, 300)]
    [InlineData(false, -30)]
    public async Task Validate_ReferenceClientAccessToken_ExpectReferenceToken(bool validateLifetime, int accessTokenExpiresAt)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<IServerTokenDecoder>();

        var client = new Client("app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var accessToken = new ClientAccessToken(client, "resource1", DiscoveryDocument.Issuer, ScopeConstants.OpenId, accessTokenExpiresAt)
        {
            Jkt = "jkt"
        };
        await AddEntity(accessToken);

        // Act
        var tokenResult = await tokenDecoder.Validate(
            accessToken.Reference,
            new ServerTokenDecodeArguments
            {
                ValidateLifetime = validateLifetime,
                Audiences = [accessToken.Audience],
                TokenTypes = [TokenTypeHeaderConstants.AccessToken]
            },
            CancellationToken.None);

        // Assert
        Assert.NotNull(tokenResult);
        Assert.Equal(client.Id, tokenResult.ClientId);
        Assert.Equal(accessToken.Id.ToString(), tokenResult.Jti);
        Assert.Equal(client.Id, tokenResult.Sub);
        Assert.Equal(TokenTypeHeaderConstants.AccessToken, tokenResult.Typ);
        Assert.Equal(accessToken.Scope!.Split(' '), tokenResult.Scope);
        Assert.Null(tokenResult.GrantId);
        Assert.Equal(accessToken.Jkt, tokenResult.Jkt);
        Assert.Null(tokenResult.Sid);
        Assert.Null(tokenResult.Act);
        Assert.Null(tokenResult.MayAct);
    }

    [Theory]
    [InlineData(true, 300)]
    [InlineData(false, -30)]
    public async Task Validate_ReferenceGrantAccessToken_ExpectReferenceToken(bool validateLifetime, int accessTokenExpiresAt)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var tokenDecoder = serviceProvider.GetRequiredService<IServerTokenDecoder>();

        var subject = new SubjectIdentifier();
        var session = new Session(subject);
        var client = new Client("app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var grant = new AuthorizationCodeGrant(session, client, subject.Id, levelOfAssurance);
        var accessToken = new GrantAccessToken(grant, "resource1", DiscoveryDocument.Issuer, ScopeConstants.OpenId, accessTokenExpiresAt)
        {
            SubjectActor = Guid.NewGuid().ToString(),
            SubjectMayAct = Guid.NewGuid().ToString()
        };
        await AddEntity(accessToken);

        // Act
        var tokenResult = await tokenDecoder.Validate(
            accessToken.Reference,
            new ServerTokenDecodeArguments
            {
                ValidateLifetime = validateLifetime,
                Audiences = [accessToken.Audience],
                TokenTypes = [TokenTypeHeaderConstants.AccessToken]
            },
            CancellationToken.None);

        // Assert
        Assert.NotNull(tokenResult);
        Assert.Equal(client.Id, tokenResult.ClientId);
        Assert.Equal(accessToken.Id.ToString(), tokenResult.Jti);
        Assert.Equal(subject.Id, tokenResult.Sub);
        Assert.Equal(TokenTypeHeaderConstants.AccessToken, tokenResult.Typ);
        Assert.Equal(accessToken.Scope!.Split(' '), tokenResult.Scope);
        Assert.Equal(grant.Id, tokenResult.GrantId);
        Assert.Null(tokenResult.Jkt);
        Assert.Equal(session.Id, tokenResult.Sid);
        Assert.NotNull(tokenResult.Act);
        Assert.Equal(accessToken.SubjectActor, tokenResult.Act.Sub);
        Assert.NotNull(tokenResult.MayAct);
        Assert.Equal(accessToken.SubjectMayAct, tokenResult.MayAct.Sub);
    }
}