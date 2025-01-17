using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.FeatureManagement;

namespace AuthServer.Endpoints.Filters;

internal class FeatureFilter(Func<EndpointFilterInvocationContext, string> featureNameFilter)
    : IEndpointFilter
{
    public FeatureFilter(string featureName): this(_ => featureName)
    {
    }

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var featureName = featureNameFilter(context);
        var featureManager = context.HttpContext.RequestServices.GetRequiredService<IFeatureManagerSnapshot>();
        if (await featureManager.IsEnabledAsync(featureName))
        {
            return await next(context);
        }
        
        context.HttpContext.Response.StatusCode = StatusCodes.Status404NotFound;
        return null;
    }
}