using Microsoft.AspNetCore.Http;

namespace AuthServer.Endpoints.Filters;

internal class DailyCacheFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        context.HttpContext.Response.Headers.CacheControl = "max-age=86400, public, must-revalidate";
        return await next(context);
    }
}