using AuthServer.Authorization.Models;

namespace AuthServer.Authorization.Abstractions;

internal interface IScopeResourceService
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="scopes"></param>
    /// <param name="resources"></param>
    /// <param name="authorizationGrantId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<ScopeResourceValidationResult> ValidateScopeResourceForGrant(
        IReadOnlyCollection<string> scopes,
        IReadOnlyCollection<string> resources,
        string authorizationGrantId,
        CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="scopes"></param>
    /// <param name="resources"></param>
    /// <param name="clientId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<ScopeResourceValidationResult> ValidateScopeResourceForClient(
        IReadOnlyCollection<string> scopes,
        IReadOnlyCollection<string> resources,
        string clientId,
        CancellationToken cancellationToken);
}