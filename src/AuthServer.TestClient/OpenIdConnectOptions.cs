using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth.Claims;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.TestClient;

public class OpenIdConnectOptions : RemoteAuthenticationOptions
{
    public string Authority { get; set; } = null!;
    public string MetadataAddress { get; set; } = null!;
    public string ClientId { get; set; } = null!;
    public string? ClientSecret { get; set; }
    public CookieBuilder NonceCookie { get; set; } = null!;
    public IConfigurationManager<OpenIdConnectConfiguration> ConfigurationManager { get; set; } = null!;
    public TokenValidationParameters TokenValidationParameters { get; set; } = null!;
    public SecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; } = null!;
    public SecureDataFormat<string> StringDataFormat { get; set; } = null!;
    public OpenIdConnectProtocolValidator ProtocolValidator { get; set; } = null!;
    public ClaimActionCollection ClaimActions { get; } = [];
}