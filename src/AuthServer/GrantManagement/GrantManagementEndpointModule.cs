using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Endpoints.Filters;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AuthServer.GrantManagement;

internal class GrantManagementEndpointModule : IEndpointModule
{
    public void RegisterEndpoint(IEndpointRouteBuilder endpointRouteBuilder)
    {
        var revokeRouteBuilder = endpointRouteBuilder.MapDelete(
            "connect/grants/{grant_id}",
            (HttpContext httpContext, [FromKeyedServices("GrantManagementRevoke")] IEndpointHandler endpointHandler,
                CancellationToken cancellationToken) => endpointHandler.Handle(httpContext, cancellationToken));

        revokeRouteBuilder
            .WithDisplayName("OpenId Connect GrantManagement Revoke")
            .WithName("OpenId Connect GrantManagement Revoke")
            .WithDescription("Endpoint to revoke grants")
            .WithGroupName("GrantManagement")
            .RequireAuthorization(AuthorizationConstants.GrantManagementRevoke)
            .AddEndpointFilter<NoCacheFilter>()
            .AddEndpointFilter<NoReferrerFilter>()
            .AddEndpointFilter(new FeatureFilter(FeatureFlags.GrantManagementRevoke));

        var queryRouteBuilder = endpointRouteBuilder.MapGet(
            "connect/grants/{grant_id}",
            (HttpContext httpContext, [FromKeyedServices("GrantManagementQuery")] IEndpointHandler endpointHandler,
                CancellationToken cancellationToken) => endpointHandler.Handle(httpContext, cancellationToken));

        queryRouteBuilder
            .WithDisplayName("OpenId Connect GrantManagement Query")
            .WithName("OpenId Connect GrantManagement Query")
            .WithDescription("Endpoint to query grants")
            .WithGroupName("GrantManagement")
            .RequireAuthorization(AuthorizationConstants.GrantManagementQuery)
            .AddEndpointFilter<NoCacheFilter>()
            .AddEndpointFilter<NoReferrerFilter>()
            .AddEndpointFilter(new FeatureFilter(FeatureFlags.GrantManagementQuery));
    }
}