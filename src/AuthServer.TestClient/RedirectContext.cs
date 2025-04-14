using Microsoft.AspNetCore.Authentication;

namespace AuthServer.TestClient;

public sealed class RedirectContext : PropertiesContext<OpenIdConnectOptions>
{
    public RedirectContext(HttpContext context, AuthenticationScheme scheme, OpenIdConnectOptions options, AuthenticationProperties? properties)
        : base(context, scheme, options, properties)
    {
    }
}