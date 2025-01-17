using AuthServer.Core;
using AuthServer.Endpoints.Responses;
using AuthServer.Extensions;
using AuthServer.Options;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.FeatureManagement;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.Endpoints;
internal static class JwksDocumentEndpoint
{
    public static async Task<IResult> HandleJwksDocument(
        [FromServices] IOptionsSnapshot<JwksDocument> jwksDocumentOptions,
        [FromServices] IFeatureManagerSnapshot featureManagerSnapshot)
    {
        if (!await featureManagerSnapshot.IsEnabledAsync(FeatureFlags.Jwks))
        {
            return Results.NotFound();
        }
        
        var keys = new List<JwkDto>();
        keys.AddRange(GetSigningJsonWebKeys(jwksDocumentOptions.Value));
        keys.AddRange(GetEncryptionJsonWebKeys(jwksDocumentOptions.Value));

        var response = new GetJwksResponse
        {
            Keys = keys
        };

        return Results.Ok(response);
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
                key.X =  jsonWebKey.X;
                key.Y = jsonWebKey.Y;
                break;
            case RsaSecurityKey:
                key.Modulus = jsonWebKey.N;
                key.Exponent = jsonWebKey.E;
                break;
            case X509SecurityKey:
                key.X509Thumbprint = jsonWebKey.X5t;
                break;
        }
    }
}