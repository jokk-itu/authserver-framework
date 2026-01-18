namespace AuthServer.UserInterface.Abstractions;

public interface IDeviceCodeGrantService
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="subjectIdentifier"></param>
    /// <param name="deviceAuthorizeDto"></param>
    /// <param name="amr"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<string> HandleDeviceCodeAuthorizationGrant(string subjectIdentifier, DeviceAuthorizeDto deviceAuthorizeDto, IReadOnlyCollection<string> amr, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="userCode"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task RedeemUserCode(string userCode, CancellationToken cancellationToken);
}