using Microsoft.Extensions.Options;

namespace AuthServer.TestClient;

public class ConfigureOpenIdConnectOptions : IConfigureOptions<OpenIdConnectOptions>
{
    private readonly IConfiguration _configuration;

    public ConfigureOpenIdConnectOptions(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    
    public void Configure(OpenIdConnectOptions options)
    {
        var openIdConnectConfiguration = _configuration.GetSection("OpenIdConnect");
        options.Authority = openIdConnectConfiguration.GetValue<string>("Authority")!;
        options.MetadataAddress = $"{options.Authority}{openIdConnectConfiguration.GetValue<string>("DiscoveryPath")}";
        options.ClientId = openIdConnectConfiguration.GetValue<string>("ClientId")!;
        options.ClientSecret = openIdConnectConfiguration.GetValue<string>("ClientSecret");
    }
}