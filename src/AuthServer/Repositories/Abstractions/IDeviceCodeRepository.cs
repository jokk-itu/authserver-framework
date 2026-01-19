using AuthServer.Entities;

namespace AuthServer.Repositories.Abstractions;
internal interface IDeviceCodeRepository
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="deviceCodeId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task UpdateInterval(string deviceCodeId, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="deviceCodeId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task UpdatePoll(string deviceCodeId, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="userCode"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<DeviceCode?> GetDeviceCode(string userCode, CancellationToken cancellationToken);
}