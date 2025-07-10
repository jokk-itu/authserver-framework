using AuthServer.Authorization.Models;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Extensions;
using Microsoft.AspNetCore.Http;

namespace AuthServer.DeviceAuthorization;

internal class DeviceAuthorizationEndpointHandler : IEndpointHandler
{
    private readonly IRequestAccessor<DeviceAuthorizationRequest> _requestAccessor;
    private readonly IRequestHandler<DeviceAuthorizationRequest, DeviceAuthorizationResponse> _requestHandler;

    public DeviceAuthorizationEndpointHandler(
        IRequestAccessor<DeviceAuthorizationRequest> requestAccessor,
        IRequestHandler<DeviceAuthorizationRequest, DeviceAuthorizationResponse> requestHandler)
    {
        _requestAccessor = requestAccessor;
        _requestHandler = requestHandler;
    }
    
    public async Task<IResult> Handle(HttpContext httpContext, CancellationToken cancellationToken)
    {
        var request = await _requestAccessor.GetRequest(httpContext.Request);
        var response = await _requestHandler.Handle(request, cancellationToken);
        return response.Match(
            result => Results.Ok(new PostDeviceAuthorizationResponse
            {
                DeviceCode = result.DeviceCode,
                UserCode = result.UserCode,
                VerificationUri = result.VerificationUri,
                VerificationUriComplete = result.VerificationUriComplete,
                ExpiresIn = result.ExpiresIn,
                Interval = result.Interval
            }),
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