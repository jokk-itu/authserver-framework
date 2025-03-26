using AuthServer.Enums;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.Options;
public record SigningKey(AsymmetricSecurityKey Key, SigningAlg Alg);