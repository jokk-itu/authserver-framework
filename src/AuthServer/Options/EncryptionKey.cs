using AuthServer.Enums;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.Options;
public record EncryptionKey(AsymmetricSecurityKey Key, EncryptionAlg Alg);
