﻿using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.Helpers;

internal static class CryptographyHelper
{
    private const string Characters = "0123456789!?$()[]{}abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

    private const string LatinAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    public static string GetRandomString(int length)
    {
        return RandomNumberGenerator.GetString(Characters, length);
    }

    public static string GetUserCode()
    {
        return RandomNumberGenerator.GetString(LatinAlphabet, 8);
    }

    /// <summary>
    /// Get the hash of a token as defined in openid-connect-core-1_0.
    /// <remarks>https://openid.net/specs/openid-connect-core-1_0.html#ImplicitTokenValidation</remarks>
    /// </summary>
    /// <param name="token"></param>
    /// <returns></returns>
    public static string HashToken(string token)
    {
        var asciiToken = Encoding.ASCII.GetBytes(token);
        var hashedToken = SHA256.HashData(asciiToken);
        var halfToken = hashedToken.Take(hashedToken.Length / 2).ToArray();
        return Base64UrlEncoder.Encode(halfToken);
    }

    /// <summary>
    /// Compute the thumbprint of a JWK as defined in rfc7638.
    /// <remarks>https://datatracker.ietf.org/doc/html/rfc7638</remarks>
    /// </summary>
    /// <param name="jwkJson"></param>
    /// <returns></returns>
    public static string ComputeJwkThumbprint(string jwkJson)
    {
        var securityKey = new JsonWebKey(jwkJson);
        var thumbprintBytes = securityKey.ComputeJwkThumbprint();
        return Base64UrlEncoder.Encode(thumbprintBytes);
    }

    public static string Sha256(this string data)
    {
        var bytes = Encoding.Default.GetBytes(data);
        var hash = SHA256.HashData(bytes);
        var builder = new StringBuilder();
        foreach (var b in hash)
        {
            builder.Append(b.ToString("X2"));
        }

        return builder.ToString();
    }

    public static string HashPassword(string password)
    {
        const int iterations = 100000;
        const int requestedSize = 256 / 8;
        const int saltSize = 128 / 8;
        const KeyDerivationPrf derivation = KeyDerivationPrf.HMACSHA512;

        var salt = RandomNumberGenerator.GetBytes(saltSize);
        var subkey = KeyDerivation.Pbkdf2(password, salt, derivation, iterations, requestedSize);

        var outputBytes = new byte[13 + salt.Length + subkey.Length];
        outputBytes[0] = 0x01; // format marker

        WriteNetworkByteOrder(outputBytes, 1, (uint)derivation);
        WriteNetworkByteOrder(outputBytes, 5, (uint)iterations);
        WriteNetworkByteOrder(outputBytes, 9, (uint)saltSize);

        Buffer.BlockCopy(salt, 0, outputBytes, 13, salt.Length);
        Buffer.BlockCopy(subkey, 0, outputBytes, 13 + saltSize, subkey.Length);

        return Convert.ToBase64String(outputBytes);
    }

    public static bool VerifyPassword(string hashedPassword, string plainPassword)
    {
        var decodedHashedPassword = Convert.FromBase64String(hashedPassword);

        // Read header information
        var derivation = (KeyDerivationPrf)ReadNetworkByteOrder(decodedHashedPassword, 1);
        var iterations = (int)ReadNetworkByteOrder(decodedHashedPassword, 5);
        var saltLength = (int)ReadNetworkByteOrder(decodedHashedPassword, 9);

        var salt = new byte[saltLength];
        Buffer.BlockCopy(decodedHashedPassword, 13, salt, 0, salt.Length);

        var subkeyLength = decodedHashedPassword.Length - 13 - salt.Length;
        var expectedSubkey = new byte[subkeyLength];
        Buffer.BlockCopy(decodedHashedPassword, 13 + salt.Length, expectedSubkey, 0, expectedSubkey.Length);

        var actualSubkey = KeyDerivation.Pbkdf2(plainPassword, salt, derivation, iterations, subkeyLength);
        return CryptographicOperations.FixedTimeEquals(actualSubkey, expectedSubkey);
    }

    private static uint ReadNetworkByteOrder(byte[] buffer, int offset)
    {
        return ((uint)(buffer[offset]) << 24)
               | ((uint)(buffer[offset + 1]) << 16)
               | ((uint)(buffer[offset + 2]) << 8)
               | ((uint)(buffer[offset + 3]));
    }

    private static void WriteNetworkByteOrder(byte[] buffer, int offset, uint value)
    {
        buffer[offset + 0] = (byte)(value >> 24);
        buffer[offset + 1] = (byte)(value >> 16);
        buffer[offset + 2] = (byte)(value >> 8);
        buffer[offset + 3] = (byte)(value >> 0);
    }
}