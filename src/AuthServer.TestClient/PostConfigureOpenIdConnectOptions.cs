using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.TestClient;

public class PostConfigureOpenIdConnectOptions : IPostConfigureOptions<OpenIdConnectOptions>
{
    private readonly IDataProtectionProvider _dataProtectionProvider;

    public PostConfigureOpenIdConnectOptions(IDataProtectionProvider dataProtectionProvider)
    {
        _dataProtectionProvider = dataProtectionProvider;
    }
    
    public void PostConfigure(string? name, OpenIdConnectOptions options)
    {
        options.CorrelationCookie = new CookieBuilder
        {
            Name = "OpenIdConnect.Correlation",
            HttpOnly = true,
            IsEssential = true,
            SecurePolicy = CookieSecurePolicy.Always,
            SameSite = SameSiteMode.Strict,
            MaxAge = TimeSpan.FromMinutes(15)
        };

        options.NonceCookie = new CookieBuilder
        {
            Name = "OpenIdConnect.Nonce",
            HttpOnly = true,
            IsEssential = true,
            SecurePolicy = CookieSecurePolicy.Always,
            SameSite = SameSiteMode.Strict,
            MaxAge = TimeSpan.FromMinutes(15)
        };

        options.ProtocolValidator = new OpenIdConnectProtocolValidator
        {
            NonceLifetime = TimeSpan.FromMinutes(15),
            RequireAcr = true,
            RequireAmr = true,
            RequireAuthTime = true,
            RequireAzp = true,
            RequireNonce = true,
            RequireState = true,
            RequireSub = true,
            RequireStateValidation = false, // This is handled manually 
            RequireTimeStampInNonce = true
        };
        
        options.CallbackPath = "/signin-oidc";
        options.SaveTokens = true;
        
        options.Backchannel = new HttpClient
        {
            BaseAddress = new Uri(options.Authority),
            Timeout = options.BackchannelTimeout,
            MaxResponseContentBufferSize = 1024 * 32
        };

        options.StateDataFormat = new PropertiesDataFormat(
            _dataProtectionProvider.CreateProtector("OpenIdConnect.StateDataFormat"));
        
        options.StringDataFormat = new SecureDataFormat<string>(
            new StringSerializer(),
            _dataProtectionProvider.CreateProtector("OpenIdConnect.StringDataFormat"));
        
        options.DataProtectionProvider = _dataProtectionProvider.CreateProtector("OpenIdConnect");
        options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            options.MetadataAddress, new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever(options.Backchannel) { RequireHttps = true })
        {
            RefreshInterval = ConfigurationManager<OpenIdConnectConfiguration>.DefaultRefreshInterval,
            AutomaticRefreshInterval = ConfigurationManager<OpenIdConnectConfiguration>.DefaultAutomaticRefreshInterval
        };

        options.ClaimActions.Add(new MapAllClaimsAction());

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidAudience = options.ClientId,
            ValidIssuer = options.Authority,
            ClockSkew = TimeSpan.Zero,
            NameClaimType = "name",
            RoleClaimType = "roles"
        };
    }
    
    private sealed class StringSerializer : IDataSerializer<string>
    {
        public string Deserialize(byte[] data)
        {
            return Encoding.UTF8.GetString(data);
        }

        public byte[] Serialize(string model)
        {
            return Encoding.UTF8.GetBytes(model);
        }
    }
}