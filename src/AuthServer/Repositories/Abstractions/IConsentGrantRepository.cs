using AuthServer.Entities;

namespace AuthServer.Repositories.Abstractions;
internal interface IConsentGrantRepository
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="subjectIdentifier"></param>
    /// <param name="clientId"></param>
    /// <param name="scopes"></param>
    /// <param name="claims"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task CreateOrUpdateClientConsent(string subjectIdentifier, string clientId, IEnumerable<string> scopes, IEnumerable<string> claims, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="authorizationGrantId"></param>
    /// <param name="scopes"></param>
    /// <param name="claims"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task CreateConsent(string authorizationGrantId, IEnumerable<string> scopes, IEnumerable<string> claims, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="authorizationGrantId"></param>
    /// <param name="scopes"></param>
    /// <param name="claims"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task ReplaceConsent(string authorizationGrantId, IEnumerable<string> scopes, IEnumerable<string> claims, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="authorizationGrantId"></param>
    /// <param name="scopes"></param>
    /// <param name="claims"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task MergeConsent(string authorizationGrantId, IEnumerable<string> scopes, IEnumerable<string> claims, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="subjectIdentifier"></param>
    /// <param name="clientId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<IReadOnlyCollection<string>> GetClientConsentedScope(string subjectIdentifier, string clientId, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="subjectIdentifier"></param>
    /// <param name="clientId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<IReadOnlyCollection<string>> GetClientConsentedClaims(string subjectIdentifier, string clientId, CancellationToken cancellationToken);
}