using AuthServer.Core.Abstractions;
using AuthServer.Endpoints;
using AuthServer.Endpoints.Filters;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AuthServer.TokenByGrant;

internal class TokenEndpointModule : IEndpointModule
{
    public void RegisterEndpoint(IEndpointRouteBuilder endpointRouteBuilder)
    {
        var routeBuilder = endpointRouteBuilder
            .MapPost(
                "connect/token",
                (HttpContext httpContext, [FromKeyedServices(EndpointNameConstants.Token)] IEndpointHandler endpointHandler,
                    CancellationToken cancellationToken) => endpointHandler.Handle(httpContext, cancellationToken));

        routeBuilder
            .WithDisplayName("OpenId Connect Token")
            .WithName("OpenId Connect Token")
            .WithDescription("Endpoint to get tokens")
            .WithGroupName("Token");

        routeBuilder
            .AddEndpointFilter<NoCacheFilter>()
            .AddEndpointFilter<NoReferrerFilter>();
    }
}