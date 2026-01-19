namespace AuthServer.UserInterface.Abstractions;

internal interface IDeviceAuthorizeService
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="userCode"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<DeviceAuthorizeDto?> GetDeviceAuthorizeDto(string userCode, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<SubjectDto> GetSubject(CancellationToken cancellationToken);
}