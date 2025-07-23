using AuthServer.Entities;

namespace AuthServer.Repositories.Abstractions;

internal interface IAuthorizationGrantRepository
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="authorizationGrantId"></param>
    /// <param name="authenticationContextReference"></param>
    /// <param name="authenticationMethodReferences"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task UpdateAuthorizationGrant(string authorizationGrantId, string authenticationContextReference, IReadOnlyCollection<string> authenticationMethodReferences, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="authorizationGrantId"></param>
    /// <param name="clientId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<bool> IsActiveAuthorizationGrant(string authorizationGrantId, string clientId, CancellationToken cancellationToken);
    
    /// <summary>
    /// Creates a new authorization code grant.
    /// </summary>
    /// <param name="subjectIdentifier"></param>
    /// <param name="clientId"></param>
    /// <param name="authenticationContextReference"></param>
    /// <param name="authenticationMethodReferences"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<AuthorizationCodeGrant> CreateAuthorizationCodeGrant(string subjectIdentifier, string clientId, string authenticationContextReference, IReadOnlyCollection<string> authenticationMethodReferences, CancellationToken cancellationToken);

    /// <summary>
    /// Creates a new device code grant.
    /// </summary>
    /// <param name="subjectIdentifier"></param>
    /// <param name="clientId"></param>
    /// <param name="authenticationContextReference"></param>
    /// <param name="authenticationMethodReferences"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<DeviceCodeGrant> CreateDeviceCodeGrant(string subjectIdentifier, string clientId, string authenticationContextReference, IReadOnlyCollection<string> authenticationMethodReferences, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="authorizationGrantId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<AuthorizationCodeGrant?> GetActiveAuthorizationCodeGrant(string authorizationGrantId, CancellationToken cancellationToken);

    /// <summary>
    /// Revokes grant if active, with all relations.
    /// </summary>
    /// <param name="authorizationGrantId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task RevokeGrant(string authorizationGrantId, CancellationToken cancellationToken);

    /// <summary>
    /// Revoke inactive grants, based on <paramref name="batchSize"/>.
    /// </summary>
    /// <param name="batchSize"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task RevokeExpiredGrants(int batchSize, CancellationToken cancellationToken);
}