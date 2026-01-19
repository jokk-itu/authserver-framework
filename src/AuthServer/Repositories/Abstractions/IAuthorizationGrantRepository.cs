using AuthServer.Entities;

namespace AuthServer.Repositories.Abstractions;

internal interface IAuthorizationGrantRepository
{
    /// <summary>
    /// Updates the AuthorizationCodeGrant with new authentication details.
    /// </summary>
    /// <param name="authorizationCodeGrantId"></param>
    /// <param name="authenticationContextReference"></param>
    /// <param name="authenticationMethodReferences"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task UpdateAuthorizationCodeGrant(string authorizationCodeGrantId, string authenticationContextReference, IReadOnlyCollection<string> authenticationMethodReferences, CancellationToken cancellationToken);

    /// <summary>
    /// Updates the DeviceCodeGrant with new authentication details, and links the DeviceCode.
    /// </summary>
    /// <param name="deviceCodeGrantId"></param>
    /// <param name="deviceCodeId"></param>
    /// <param name="authenticationContextReference"></param>
    /// <param name="authenticationMethodReferences"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task UpdateDeviceCodeGrant(string deviceCodeGrantId, string deviceCodeId, string authenticationContextReference, IReadOnlyCollection<string> authenticationMethodReferences, CancellationToken cancellationToken);

    /// <summary>
    /// Returns whether the authorization grant is active.
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
    /// <param name="deviceCodeId"></param>
    /// <param name="authenticationContextReference"></param>
    /// <param name="authenticationMethodReferences"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<DeviceCodeGrant> CreateDeviceCodeGrant(string subjectIdentifier, string clientId, string deviceCodeId, string authenticationContextReference, IReadOnlyCollection<string> authenticationMethodReferences, CancellationToken cancellationToken);

    /// <summary>
    /// Returns the active AuthorizationCodeGrant, or null if inactive or not found.
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