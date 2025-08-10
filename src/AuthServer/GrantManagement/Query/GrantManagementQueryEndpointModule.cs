using AuthServer.Authorization.OAuthToken;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Endpoints;
using AuthServer.Endpoints.Filters;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AuthServer.GrantManagement.Query;

internal class GrantManagementQueryEndpointModule : IEndpointModule
{
    public void RegisterEndpoint(IEndpointRouteBuilder endpointRouteBuilder)
    {
        var queryRouteBuilder = endpointRouteBuilder.MapGet(
            "connect/grants/{grant_id}",
            (HttpContext httpContext, [FromKeyedServices(EndpointNameConstants.GrantManagementQuery)] IEndpointHandler endpointHandler,
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