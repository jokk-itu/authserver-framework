namespace AuthServer.Authentication.Abstractions;

internal interface IClientLogoutService
{
    /// <summary>
    /// Requests logout for all provided clients at the backchannel logout endpoint.
    /// </summary>
    /// <param name="clientIds"></param>
    /// <param name="sessionId"></param>
    /// <param name="subjectIdentifier"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task Logout(IReadOnlyCollection<string> clientIds, string? sessionId, string? subjectIdentifier, CancellationToken cancellationToken);
}