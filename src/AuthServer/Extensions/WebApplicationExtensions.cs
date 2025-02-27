using AuthServer.Core.Abstractions;
using AuthServer.Endpoints;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AuthServer.Extensions;
public static class WebApplicationExtensions
{
    public static void UseAuthServer(this WebApplication app)
    {
        app.UseMiddleware<OAuthErrorMiddleware>();

        var modules = app.Services.GetServices<IEndpointModule>();
        foreach (var module in modules)
        {
            module.RegisterEndpoint(app);
            app.Logger.LogDebug("Registered endpoint {Endpoint}", nameof(module));
        }
    }
}
