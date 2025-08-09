using AuthServer.Authorization.OAuthToken;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Endpoints;
using AuthServer.Endpoints.Filters;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AuthServer.GrantManagement.Revoke;

internal class GrantManagementRevokeEndpointModule : IEndpointModule
{
    public void RegisterEndpoint(IEndpointRouteBuilder endpointRouteBuilder)
    {
        var revokeRouteBuilder = endpointRouteBuilder.MapDelete(
            "connect/grants/{grant_id}",
            (HttpContext httpContext, [FromKeyedServices(EndpointNameConstants.GrantManagementRevoke)] IEndpointHandler endpointHandler,
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
    }
}