using Microsoft.Extensions.Options;

namespace AuthServer.Options;

internal class PostConfigureTokenValidationOptions : IPostConfigureOptions<TokenValidationOptions>
{
    public void PostConfigure(string? name, TokenValidationOptions options)
    {
        if (options.ClockSkew == TimeSpan.Zero)
        {
            options.ClockSkew = TimeSpan.FromSeconds(10);
        }

        if (options.ClientTokenLifetimeWindow == TimeSpan.Zero)
        {
            options.ClientTokenLifetimeWindow = TimeSpan.FromSeconds(60);
        }
    }
}