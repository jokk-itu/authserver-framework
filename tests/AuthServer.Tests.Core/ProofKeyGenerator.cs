using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using AuthServer.Constants;

namespace AuthServer.Tests.Core;

public static class ProofKeyGenerator
{
    public static ProofKey GetProofKeyForCodeExchange(string? codeChallengeMethod = null)
    {
        codeChallengeMethod ??= CodeChallengeMethodConstants.S256;
        var codeVerifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(64));
        var hashed = HashCodeVerifier(codeVerifier, codeChallengeMethod);
        var codeChallenge = Base64UrlEncoder.Encode(hashed);
        return new ProofKey(codeChallenge, codeVerifier, codeChallengeMethod);
    }

    private static byte[] HashCodeVerifier(string codeVerifier, string codeChallengeMethod)
    {
        var bytes = Encoding.UTF8.GetBytes(codeVerifier);
        if (codeChallengeMethod == CodeChallengeMethodConstants.S256)
        {
            return SHA256.HashData(bytes);
        }

        if (codeChallengeMethod == CodeChallengeMethodConstants.S384)
        {
            return SHA384.HashData(bytes);
        }

        if (codeChallengeMethod == CodeChallengeMethodConstants.S512)
        {
            return SHA512.HashData(bytes);
        }

        throw new InvalidOperationException($"CodeChallengeMethod {codeChallengeMethod} is unsupported");
    }
}

public record ProofKey(string CodeChallenge, string CodeVerifier, string CodeChallengeMethod);