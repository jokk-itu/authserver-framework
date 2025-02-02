using AuthServer.Repositories.Models;

namespace AuthServer.Repositories.Abstractions;
internal interface IConsentRepository
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
    Task CreateOrUpdateClientConsent(string subjectIdentifier, string clientId, IReadOnlyCollection<string> scopes, IReadOnlyCollection<string> claims, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="authorizationGrantId"></param>
    /// <param name="scopes"></param>
    /// <param name="resources"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task CreateGrantConsent(string authorizationGrantId, IReadOnlyCollection<string> scopes, IReadOnlyCollection<string> resources, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="authorizationGrantId"></param>
    /// <param name="scopes"></param>
    /// <param name="resources"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task ReplaceGrantConsent(string authorizationGrantId, IReadOnlyCollection<string> scopes, IReadOnlyCollection<string> resources, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="authorizationGrantId"></param>
    /// <param name="scopes"></param>
    /// <param name="resources"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task MergeGrantConsent(string authorizationGrantId, IReadOnlyCollection<string> scopes, IReadOnlyCollection<string> resources, CancellationToken cancellationToken);

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