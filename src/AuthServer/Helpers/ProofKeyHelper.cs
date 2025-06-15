using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using AuthServer.Constants;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.Helpers;

internal static class ProofKeyHelper
{
    public static bool IsCodeChallengeMethodValid(string? codeChallengeMethod)
        => CodeChallengeMethodConstants.CodeChallengeMethods.Contains(codeChallengeMethod);

    public static bool IsCodeChallengeValid(string? codeChallenge)
    {
        if (string.IsNullOrWhiteSpace(codeChallenge))
        {
            return false;
        }

        return IsCodeValid(codeChallenge);
    }

    public static bool IsCodeVerifierValid(string? codeVerifier, string? codeChallenge, string? codeChallengeMethod)
    {
        if (string.IsNullOrWhiteSpace(codeVerifier)
            || string.IsNullOrWhiteSpace(codeChallenge)
            || string.IsNullOrEmpty(codeChallengeMethod))
        {
            return false;
        }

        var isCodeVerifierFormatValid = IsCodeValid(codeVerifier);
        if (!isCodeVerifierFormatValid)
        {
            return false;
        }

        var hashed = HashCodeVerifier(codeVerifier, codeChallengeMethod);
        var encoded = Base64UrlEncoder.Encode(hashed);
        return encoded == codeChallenge;
    }

    private static bool IsCodeValid(string code) => Regex.IsMatch(
        code,
        "^[0-9a-zA-Z-_~.]{43,128}$",
        RegexOptions.Compiled,
        TimeSpan.FromMilliseconds(100));

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

        throw new SecurityException($"CodeChallengeMethod {codeChallengeMethod} is unsupported");
    }
}