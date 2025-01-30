using AuthServer.Repositories.Models;

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
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task CreateGrantConsent(string authorizationGrantId, IEnumerable<string> scopes, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="authorizationGrantId"></param>
    /// <param name="scopes"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task ReplaceGrantConsent(string authorizationGrantId, IEnumerable<string> scopes, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="authorizationGrantId"></param>
    /// <param name="scopes"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task MergeGrantConsent(string authorizationGrantId, IEnumerable<string> scopes, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="subjectIdentifier"></param>
    /// <param name="clientId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<IReadOnlyCollection<string>> GetClientConsentedScopes(string subjectIdentifier, string clientId, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="subjectIdentifier"></param>
    /// <param name="clientId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<IReadOnlyCollection<string>> GetClientConsentedClaims(string subjectIdentifier, string clientId, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="authorizationGrantId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<IReadOnlyCollection<ScopeDto>> GetGrantConsentedScopes(string authorizationGrantId, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="authorizationGrantId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<IReadOnlyCollection<string>> GetGrantConsentedClaims(string authorizationGrantId, CancellationToken cancellationToken);
}