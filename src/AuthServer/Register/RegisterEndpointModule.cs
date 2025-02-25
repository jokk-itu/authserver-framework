using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Endpoints;
using AuthServer.Endpoints.Filters;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AuthServer.Register;

internal class RegisterEndpointModule : IEndpointModule
{
    public void RegisterEndpoint(IEndpointRouteBuilder endpointRouteBuilder)
    {
        var postRegisterBuilder = endpointRouteBuilder.MapMethods(
            "connect/register",
            ["POST"],
            (HttpContext httpContext, [FromKeyedServices(EndpointNameConstants.Register)] IEndpointHandler endpointHandler,
                CancellationToken cancellationToken) => endpointHandler.Handle(httpContext, cancellationToken));

        postRegisterBuilder
            .WithDisplayName("OpenId Connect Dynamic Registration")
            .WithName("OpenId Connect Dynamic Registration")
            .WithDescription("Endpoint to register a client")
            .WithGroupName("Register");

        postRegisterBuilder
            .AddEndpointFilter<NoCacheFilter>()
            .AddEndpointFilter<NoReferrerFilter>()
            .AddEndpointFilter(new FeatureFilter(FeatureFlags.RegisterPost));

        var manageRegisterBuilder = endpointRouteBuilder
            .MapMethods(
                "connect/register",
                ["GET", "PUT", "DELETE"],
                (HttpContext httpContext, [FromKeyedServices(EndpointNameConstants.Register)] IEndpointHandler endpointHandler,
                    CancellationToken cancellationToken) => endpointHandler.Handle(httpContext, cancellationToken));

        manageRegisterBuilder
            .WithDisplayName("OpenId Connect Dynamic Management")
            .WithName("OpenId Connect Dynamic Management")
            .WithDescription("Endpoint to manage a client")
            .WithGroupName("Register");

        manageRegisterBuilder
            .RequireAuthorization(AuthorizationConstants.Register);

        manageRegisterBuilder
            .AddEndpointFilter<NoCacheFilter>()
            .AddEndpointFilter<NoReferrerFilter>()
            .AddEndpointFilter(new FeatureFilter(ctx =>
            {
                return ctx.HttpContext.Request.Method switch
                {
                    "GET" => FeatureFlags.RegisterGet,
                    "PUT" => FeatureFlags.RegisterPut,
                    "DELETE" => FeatureFlags.RegisterDelete,
                    _ => throw new NotSupportedException()
                };
            }));
    }
}