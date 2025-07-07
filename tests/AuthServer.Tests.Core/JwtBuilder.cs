using System.Text.Json;
using AuthServer.Constants;
using AuthServer.Enums;
using AuthServer.Extensions;
using AuthServer.Options;
using AuthServer.TokenDecoders;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using AuthServer.Endpoints.Abstractions;

namespace AuthServer.Tests.Core;
public class JwtBuilder
{
    private readonly DiscoveryDocument _discoveryDocument;
    private readonly JwksDocument _jwksDocument;
    private readonly IEndpointResolver _endpointResolver;

    public JwtBuilder(
        DiscoveryDocument discoveryDocument,
        JwksDocument jwksDocument,
        IEndpointResolver endpointResolver)
    {
        _discoveryDocument = discoveryDocument;
        _jwksDocument = jwksDocument;
        _endpointResolver = endpointResolver;
    }

    public string GetPrivateKeyJwt(string clientId, string privateJwks, ClientTokenAudience audience)
    {
        var jwks = JsonWebKeySet.Create(privateJwks);
        var jsonWebKey = jwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(jsonWebKey, jsonWebKey.Alg);
        var now = DateTime.UtcNow;
        var claims = new Dictionary<string, object>
        {
            { ClaimNameConstants.Sub, clientId }
        };
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(30),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = MapToAudience(audience),
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken,
            Claims = claims
        });
    }

    public string GetEncryptedPrivateKeyJwt(string clientId, string privateJwks, ClientTokenAudience audience)
    {
        var jwks = JsonWebKeySet.Create(privateJwks);
        var signKey = jwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var encryptionKey = _jwksDocument.GetEncryptionKey(EncryptionAlg.RsaPKCS1);
        var signingCredentials = new SigningCredentials(signKey, signKey.Alg);
        var encryptingCredentials = new EncryptingCredentials(encryptionKey, JweAlgConstants.RsaPKCS1, JweEncConstants.Aes128CbcHmacSha256);
        var now = DateTime.UtcNow;
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(30),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            EncryptingCredentials = encryptingCredentials,
            Audience = MapToAudience(audience),
            TokenType = TokenTypeHeaderConstants.PrivateKeyToken
        });
    }

    public string GetRequestObjectJwt(Dictionary<string, object> claims, string clientId, string privateJwks, ClientTokenAudience audience)
    {
        var jwks = JsonWebKeySet.Create(privateJwks);
        var jsonWebKey = jwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var signingCredentials = new SigningCredentials(jsonWebKey, jsonWebKey.Alg);
        var now = DateTime.UtcNow;
        claims.Add(ClaimNameConstants.Sub, clientId);
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(30),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = MapToAudience(audience),
            TokenType = TokenTypeHeaderConstants.RequestObjectToken,
            Claims = claims
        });
    }

    public string GetIdToken(string clientId, string grantId, string subject, string sessionId, IReadOnlyCollection<string> amr, string acr)
    {
        var key = _jwksDocument.GetTokenSigningKey();
        var signingCredentials = new SigningCredentials(key.Key, key.Alg.GetDescription());
        var now = DateTime.UtcNow;

        var claims = new Dictionary<string, object>
        {
            { ClaimNameConstants.Sub, subject },
            { ClaimNameConstants.Sid, sessionId },
            { ClaimNameConstants.GrantId, grantId },
            { ClaimNameConstants.Acr, acr },
            { ClaimNameConstants.Amr, JsonSerializer.SerializeToElement(amr) }
        };

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _discoveryDocument.Issuer,
            NotBefore = now,
            Expires = now.AddSeconds(30),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = clientId,
            TokenType = TokenTypeHeaderConstants.IdToken,
            Claims = claims
        });
    }

    public string GetRefreshToken(string clientId, string authorizationGrantId, string jti)
    {
        var key = _jwksDocument.GetTokenSigningKey();
        var signingCredentials = new SigningCredentials(key.Key, key.Alg.GetDescription());
        var now = DateTime.UtcNow;

        var claims = new Dictionary<string, object>
        {
            { ClaimNameConstants.Jti, jti },
            { ClaimNameConstants.GrantId, authorizationGrantId }
        };

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _discoveryDocument.Issuer,
            NotBefore = now,
            Expires = now.AddSeconds(3600),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = clientId,
            TokenType = TokenTypeHeaderConstants.RefreshToken,
            Claims = claims
        });
    }

    public string GetAccessToken(string clientId, string? jkt = null)
    {
        var key = _jwksDocument.GetTokenSigningKey();
        var signingCredentials = new SigningCredentials(key.Key, key.Alg.GetDescription());
        var now = DateTime.UtcNow;
        
        var claims = new Dictionary<string, object>
        {
            { ClaimNameConstants.ClientId, clientId }
        };

        if (jkt is not null)
        {
            claims.Add(ClaimNameConstants.Cnf, new Dictionary<string, object>
            {
                { ClaimNameConstants.Jkt, jkt }
            });
        }
        
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _discoveryDocument.Issuer,
            NotBefore = now,
            Expires = now.AddSeconds(3600),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = _discoveryDocument.Issuer,
            TokenType = TokenTypeHeaderConstants.AccessToken,
            Claims = claims
        });
    }

    public string GetDPoPToken(Dictionary<string, object> claims, string clientId, ClientJwkBuilder.ClientJwks jwks, ClientTokenAudience audience)
    {
        var privateJwks = new JsonWebKeySet(jwks.PrivateJwks);
        var publicJwks = new JsonWebKeySet(jwks.PublicJwks);

        var privateJsonWebKey = privateJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);
        var publicJsonWebKey = publicJwks.Keys.First(k => k.Use == JsonWebKeyUseNames.Sig);

        var signingCredentials = new SigningCredentials(privateJsonWebKey, privateJsonWebKey.Alg);
        var now = DateTime.UtcNow;
        claims.Add(ClaimNameConstants.Sub, clientId);
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = clientId,
            NotBefore = now,
            Expires = now.AddSeconds(30),
            IssuedAt = now,
            SigningCredentials = signingCredentials,
            Audience = MapToAudience(audience),
            TokenType = TokenTypeHeaderConstants.DPoPToken,
            Claims = claims,
            AdditionalHeaderClaims = new Dictionary<string, object>
            {
                { ClaimNameConstants.Jwk, JsonSerializer.Serialize(publicJsonWebKey) }
            }
        });
    }

    private string MapToAudience(ClientTokenAudience audience)
        => audience switch
        {
            ClientTokenAudience.AuthorizationEndpoint => _endpointResolver.AuthorizationEndpoint,
            ClientTokenAudience.TokenEndpoint => _endpointResolver.TokenEndpoint,
            ClientTokenAudience.IntrospectionEndpoint => _endpointResolver.IntrospectionEndpoint,
            ClientTokenAudience.RevocationEndpoint => _endpointResolver.RevocationEndpoint,
            ClientTokenAudience.PushedAuthorizationEndpoint => _endpointResolver.PushedAuthorizationEndpoint,
            ClientTokenAudience.UserinfoEndpoint => _endpointResolver.UserinfoEndpoint,
            ClientTokenAudience.GrantManagementEndpoint => _endpointResolver.GrantManagementEndpoint,
            _ => throw new ArgumentException("unknown value", nameof(audience))
        };
}