﻿using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Endpoints;
using AuthServer.Endpoints.Filters;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AuthServer.Authorize;

internal class AuthorizeEndpointModule : IEndpointModule
{
    public void RegisterEndpoint(IEndpointRouteBuilder endpointRouteBuilder)
    {
        var routeBuilder = endpointRouteBuilder.MapMethods(
            "connect/authorize",
            ["GET", "POST"],
            (HttpContext httpContext, [FromKeyedServices(EndpointNameConstants.Authorize)] IEndpointHandler endpointHandler,
                CancellationToken cancellationToken) => endpointHandler.Handle(httpContext, cancellationToken));

        routeBuilder
            .WithDisplayName("OpenId Connect Authorize")
            .WithName("OpenId Connect Authorize")
            .WithDescription("OpenId Connect Authorize")
            .WithGroupName("Authorize");

        routeBuilder
            .AddEndpointFilter<NoCacheFilter>()
            .AddEndpointFilter<NoReferrerFilter>()
            .AddEndpointFilter(new FeatureFilter(FeatureFlags.Authorize));
    }
}