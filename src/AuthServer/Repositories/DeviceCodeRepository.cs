using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Repositories.Abstractions;

namespace AuthServer.Repositories;
internal class DeviceCodeRepository : IDeviceCodeRepository
{
    private readonly AuthorizationDbContext _authorizationDbContext;

    public DeviceCodeRepository(AuthorizationDbContext authorizationDbContext)
    {
        _authorizationDbContext = authorizationDbContext;
    }

    public async Task UpdateInterval(string deviceCodeId, CancellationToken cancellationToken)
    {
        var deviceCode = (await _authorizationDbContext.FindAsync<DeviceCode>([deviceCodeId], cancellationToken))!;
        deviceCode.IncrementInterval(5);
    }

    public async Task UpdatePoll(string deviceCodeId, CancellationToken cancellationToken)
    {
        var deviceCode = (await _authorizationDbContext.FindAsync<DeviceCode>([deviceCodeId], cancellationToken))!;
        deviceCode.UpdatePoll();
    }
}
