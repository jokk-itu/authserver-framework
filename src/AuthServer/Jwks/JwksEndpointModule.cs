using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Endpoints.Filters;
using AuthServer.Endpoints;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AuthServer.Jwks;

internal class JwksEndpointModule : IEndpointModule
{
    public void RegisterEndpoint(IEndpointRouteBuilder endpointRouteBuilder)
    {
        endpointRouteBuilder
            .MapGet(
                ".well-known/jwks",
                (HttpContext httpContext, [FromKeyedServices(EndpointNameConstants.Jwks)] IEndpointHandler endpointHandler,
                    CancellationToken cancellationToken) => endpointHandler.Handle(httpContext, cancellationToken))
            .WithDisplayName("OAuth JWKS")
            .WithName("OAuth JWKS")
            .WithDescription("Endpoint to get the jwks")
            .WithGroupName("Configuration")
            .AddEndpointFilter<DailyCacheFilter>()
            .AddEndpointFilter<NoReferrerFilter>()
            .AddEndpointFilter(new FeatureFilter(FeatureFlags.Jwks));
    }
}