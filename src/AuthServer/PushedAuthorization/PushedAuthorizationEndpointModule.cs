﻿using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Endpoints;
using AuthServer.Endpoints.Filters;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AuthServer.PushedAuthorization;

internal class PushedAuthorizationEndpointModule : IEndpointModule
{
    public void RegisterEndpoint(IEndpointRouteBuilder endpointRouteBuilder)
    {
        var routeBuilder = endpointRouteBuilder.MapMethods(
            "connect/par",
            ["POST"],
                (HttpContext httpContext, [FromKeyedServices(EndpointNameConstants.PushedAuthorization)] IEndpointHandler endpointHandler,
                    CancellationToken cancellationToken) => endpointHandler.Handle(httpContext, cancellationToken));

        routeBuilder
            .WithDisplayName("OpenId Connect Pushed Authorization")
            .WithName("OpenId Connect Pushed Authorization")
            .WithDescription("OpenId Connect Pushed Authorization")
            .WithGroupName("Authorize");

        routeBuilder
            .AddEndpointFilter<NoCacheFilter>()
            .AddEndpointFilter<NoReferrerFilter>()
            .AddEndpointFilter(new FeatureFilter(FeatureFlags.PushedAuthorization));
    }
}