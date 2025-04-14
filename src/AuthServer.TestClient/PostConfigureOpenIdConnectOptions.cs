using System.Text;
using Microsoft.AspNetCore.Authentication;
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
        
        options.CallbackPath = "signin-oidc";
        options.SaveTokens = true;
        options.BackchannelTimeout = TimeSpan.FromSeconds(2);
        
        options.Backchannel = new HttpClient
        {
            BaseAddress = new Uri(options.Authority),
            Timeout = options.BackchannelTimeout,
            MaxResponseContentBufferSize = 1024 * 8
        };

        options.StateDataFormat = new PropertiesDataFormat(
            _dataProtectionProvider.CreateProtector("OpenIdConnect.StateDataFormat"));
        
        options.StringDataFormat = new SecureDataFormat<string>(
            new StringSerializer(),
            _dataProtectionProvider.CreateProtector("OpenIdConnect.StringDataFormat"));
        
        options.DataProtectionProvider = _dataProtectionProvider.CreateProtector("OpenIdConnect");
        options.TokenValidationParameters = new TokenValidationParameters();
        options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(
            options.MetadataAddress, new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever(options.Backchannel) { RequireHttps = true })
        {
            RefreshInterval = ConfigurationManager<OpenIdConnectConfiguration>.DefaultRefreshInterval,
            AutomaticRefreshInterval = ConfigurationManager<OpenIdConnectConfiguration>.DefaultAutomaticRefreshInterval
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