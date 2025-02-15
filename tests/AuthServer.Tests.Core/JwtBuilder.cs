using System.Text.Json;
using AuthServer.Constants;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Extensions;
using AuthServer.Options;
using AuthServer.TokenDecoders;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.Tests.Core;
public class JwtBuilder
{
    private readonly DiscoveryDocument _discoveryDocument;
    private readonly JwksDocument _jwksDocument;

    public JwtBuilder(
        DiscoveryDocument discoveryDocument,
        JwksDocument jwksDocument)
    {
        _discoveryDocument = discoveryDocument;
        _jwksDocument = jwksDocument;
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

    public string GetAccessToken(string clientId)
    {
        var key = _jwksDocument.GetTokenSigningKey();
        var signingCredentials = new SigningCredentials(key.Key, key.Alg.GetDescription());
        var now = DateTime.UtcNow;
        
        var claims = new Dictionary<string, object>
        {
            { ClaimNameConstants.ClientId, clientId }
        };
        
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

    private string MapToAudience(ClientTokenAudience audience)
        => audience switch
        {
            ClientTokenAudience.AuthorizeEndpoint => _discoveryDocument.AuthorizationEndpoint,
            ClientTokenAudience.TokenEndpoint => _discoveryDocument.TokenEndpoint,
            ClientTokenAudience.IntrospectionEndpoint => _discoveryDocument.IntrospectionEndpoint,
            ClientTokenAudience.RevocationEndpoint => _discoveryDocument.RevocationEndpoint,
            ClientTokenAudience.PushedAuthorizeEndpoint => _discoveryDocument.PushedAuthorizationRequestEndpoint,
            _ => throw new ArgumentException("unknown value", nameof(audience))
        };
}