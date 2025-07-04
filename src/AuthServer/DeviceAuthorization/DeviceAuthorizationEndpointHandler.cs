using AuthServer.Core.Abstractions;
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
    
    public Task<IResult> Handle(HttpContext httpContext, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}