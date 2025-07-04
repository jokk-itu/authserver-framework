using AuthServer.Core.Abstractions;

namespace AuthServer.DeviceAuthorization;

internal class DeviceAuthorizationRequestProcessor : IRequestProcessor<DeviceAuthorizationValidatedRequest, DeviceAuthorizationResponse>
{
    public DeviceAuthorizationRequestProcessor()
    {
    }
    
    public Task<DeviceAuthorizationResponse> Process(DeviceAuthorizationValidatedRequest request, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }
}