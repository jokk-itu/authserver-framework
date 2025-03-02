using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace AuthServer.TestIdentityProvider;

public static class SecurityKeyHelper
{
    private static readonly ECDsa _ecdsa = ECDsa.Create();
    private static readonly RSA _rsa = RSA.Create(3072);

    public static readonly X509SecurityKey CertificateRsa256 = GetCertificate(HashAlgorithmName.SHA256);
    public static readonly X509SecurityKey CertificateRsa384 = GetCertificate(HashAlgorithmName.SHA384);
    public static readonly X509SecurityKey CertificateRsa512 = GetCertificate(HashAlgorithmName.SHA512);

    public static readonly ECDsaSecurityKey Ecdsa256 = GetECDsaSecurityKey();
    public static readonly ECDsaSecurityKey Ecdsa384 = GetECDsaSecurityKey();
    public static readonly ECDsaSecurityKey Ecdsa512 = GetECDsaSecurityKey();

    public static readonly ECDsaSecurityKey EcdhEs128 = GetECDsaSecurityKey();
    public static readonly ECDsaSecurityKey EcdhEs192 = GetECDsaSecurityKey();
    public static readonly ECDsaSecurityKey EcdhEs256 = GetECDsaSecurityKey();

    public static readonly RsaSecurityKey RsaOAep = GetRsaSecurityKey();
    public static readonly RsaSecurityKey RsaPkcs1 = GetRsaSecurityKey();

    public static readonly RsaSecurityKey RsaSsaPss256 = GetRsaSecurityKey();
    public static readonly RsaSecurityKey RsaSsaPss384 = GetRsaSecurityKey();
    public static readonly RsaSecurityKey RsaSsaPss512 = GetRsaSecurityKey();

    private static X509SecurityKey GetCertificate(HashAlgorithmName hashAlgorithmName)
    {
        var request = new CertificateRequest("cn=authserver", _rsa, hashAlgorithmName, RSASignaturePadding.Pkcs1);
        var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddDays(90));
        return new X509SecurityKey(certificate, Guid.NewGuid().ToString());
    }

    private static ECDsaSecurityKey GetECDsaSecurityKey() => new (_ecdsa) { KeyId = Guid.NewGuid().ToString() };
    private static RsaSecurityKey GetRsaSecurityKey() => new (_rsa){ KeyId = Guid.NewGuid().ToString() };
}
