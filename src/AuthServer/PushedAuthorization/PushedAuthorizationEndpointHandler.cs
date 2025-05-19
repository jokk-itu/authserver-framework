using AuthServer.Authorization.Models;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Endpoints.Abstractions;
using AuthServer.Endpoints.Responses;
using AuthServer.Extensions;
using Microsoft.AspNetCore.Http;

namespace AuthServer.PushedAuthorization;

internal class PushedAuthorizationEndpointHandler : IEndpointHandler
{
    private readonly IRequestAccessor<PushedAuthorizationRequest> _requestAccessor;
    private readonly IRequestHandler<PushedAuthorizationRequest, PushedAuthorizationResponse> _requestHandler;
    private readonly IEndpointResolver _endpointResolver;

    public PushedAuthorizationEndpointHandler(
        IRequestAccessor<PushedAuthorizationRequest> requestAccessor,
        IRequestHandler<PushedAuthorizationRequest, PushedAuthorizationResponse> requestHandler,
        IEndpointResolver endpointResolver)
    {
        _requestAccessor = requestAccessor;
        _requestHandler = requestHandler;
        _endpointResolver = endpointResolver;
    }

    public async Task<IResult> Handle(HttpContext httpContext, CancellationToken cancellationToken)
    {
        var request = await _requestAccessor.GetRequest(httpContext.Request);
        var response = await _requestHandler.Handle(request, cancellationToken);
        return response.Match(
            result =>
            {
                var uri =
                    $"{_endpointResolver.AuthorizationEndpoint}?{Parameter.RequestUri}={result.RequestUri}&{Parameter.ClientId}={result.ClientId}";

                var location = new Uri(uri, UriKind.Absolute);
                return Results.Created(location,
                    new PostPushedAuthorizationResponse
                    {
                        RequestUri = result.RequestUri,
                        ExpiresIn = result.ExpiresIn
                    });
            },
            error =>
            {
                if (error is DPoPNonceProcessError dPoPNonceProcessError)
                {
                    httpContext.Response.Headers[Parameter.DPoPNonce] = dPoPNonceProcessError.DPoPNonce;
                }

                return Results.Extensions.OAuthBadRequest(error);
            });
    }
}