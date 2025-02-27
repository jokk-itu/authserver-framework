using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Endpoints;
using AuthServer.Endpoints.Filters;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AuthServer.Discovery;

internal class DiscoveryEndpointModule : IEndpointModule
{
    public void RegisterEndpoint(IEndpointRouteBuilder endpointRouteBuilder)
    {
        endpointRouteBuilder
            .MapGet(
                ".well-known/openid-configuration",
                (HttpContext httpContext,
                    [FromKeyedServices(EndpointNameConstants.Discovery)] IEndpointHandler endpointHandler,
                    CancellationToken cancellationToken) => endpointHandler.Handle(httpContext, cancellationToken))
            .WithDisplayName("OpenIdConnect Configuration")
            .WithName("OpenIdConnect Configuration")
            .WithDescription("Endpoint to get the configuration")
            .WithGroupName("Configuration")
            .AddEndpointFilter<DailyCacheFilter>()
            .AddEndpointFilter<NoReferrerFilter>()
            .AddEndpointFilter(new FeatureFilter(FeatureFlags.Discovery));
    }
}