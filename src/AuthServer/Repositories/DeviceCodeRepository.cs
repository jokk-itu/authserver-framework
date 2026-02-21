using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Repositories.Abstractions;
using Microsoft.EntityFrameworkCore;

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

    public async Task<DeviceCode?> GetDeviceCode(string userCode, CancellationToken cancellationToken)
    {
        return await _authorizationDbContext
            .Set<UserCode>()
            .Where(x => x.Value == userCode)
            .Where(x => x.RedeemedAt == null)
            .Select(x => x.DeviceCode)
            .SingleOrDefaultAsync(cancellationToken);
    }
}