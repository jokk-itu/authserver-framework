using AuthServer.Core.Abstractions;
using AuthServer.Extensions;
using AuthServer.Options;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.Jwks;

internal class JwksEndpointHandler : IEndpointHandler
{
    private readonly IOptionsSnapshot<JwksDocument> _jwksDocumentOptions;

    public JwksEndpointHandler(
        IOptionsSnapshot<JwksDocument> jwksDocumentOptions)
    {
        _jwksDocumentOptions = jwksDocumentOptions;
    }

    public Task<IResult> Handle(HttpContext httpContext, CancellationToken cancellationToken)
    {
        var keys = new List<JwkDto>();
        keys.AddRange(GetSigningJsonWebKeys(_jwksDocumentOptions.Value));
        keys.AddRange(GetEncryptionJsonWebKeys(_jwksDocumentOptions.Value));

        var response = new GetJwksResponse
        {
            Keys = keys
        };

        return Task.FromResult(Results.Ok(response));
    }

    private static IEnumerable<JwkDto> GetSigningJsonWebKeys(JwksDocument jwksDocument)
    {
        foreach (var signingKey in jwksDocument.SigningKeys)
        {
            var jsonWebKey = JsonWebKeyConverter.ConvertFromSecurityKey(signingKey.Key);
            var key = new JwkDto
            {
                KeyId = jsonWebKey.Kid,
                KeyType = jsonWebKey.Kty,
                Use = JsonWebKeyUseNames.Sig,
                KeysOps = ["verify"],
                Alg = signingKey.Alg.GetDescription(),
            };
            SetKeyValues(key, jsonWebKey, signingKey.Key);
            yield return key;
        }
    }

    private static IEnumerable<JwkDto> GetEncryptionJsonWebKeys(JwksDocument jwksDocument)
    {
        foreach (var encryptionKey in jwksDocument.EncryptionKeys)
        {
            var jsonWebKey = JsonWebKeyConverter.ConvertFromSecurityKey(encryptionKey.Key);
            var key = new JwkDto
            {
                KeyId = jsonWebKey.Kid,
                KeyType = jsonWebKey.Kty,
                Use = JsonWebKeyUseNames.Enc,
                KeysOps = ["encryption"],
                Alg = encryptionKey.Alg.GetDescription(),
            };
            SetKeyValues(key, jsonWebKey, encryptionKey.Key);
            yield return key;
        }
    }

    private static void SetKeyValues(JwkDto key, JsonWebKey jsonWebKey, AsymmetricSecurityKey securityKey)
    {
        switch (securityKey)
        {
            case ECDsaSecurityKey:
                key.Curve = jsonWebKey.Crv;
                key.X = jsonWebKey.X;
                key.Y = jsonWebKey.Y;
                break;
            case RsaSecurityKey:
                key.Modulus = jsonWebKey.N;
                key.Exponent = jsonWebKey.E;
                break;
            case X509SecurityKey:
                key.X509Thumbprint = jsonWebKey.X5t;
                key.X509CertificateChain = jsonWebKey.X5c;
                key.X509ThumbprintS256 = jsonWebKey.X5tS256;
                break;
        }
    }
}