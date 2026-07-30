using AuthServer.Entities;
using AuthServer.Repositories.Models;

namespace AuthServer.Repositories.Abstractions;
internal interface IConsentRepository
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="consentDto"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task CreateOrUpdateClientConsent(ConsentDto consentDto, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="grantConsentDto"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task CreateGrantConsent(AuthorizationGrantConsentDto grantConsentDto, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="grantConsentDto"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task ReplaceGrantConsent(AuthorizationGrantConsentDto grantConsentDto, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="grantConsentDto"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task MergeGrantConsent(AuthorizationGrantConsentDto grantConsentDto, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="subjectIdentifier"></param>
    /// <param name="clientId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<IReadOnlyCollection<Consent>> GetClientConsents(string subjectIdentifier, string clientId, CancellationToken cancellationToken);

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

    /// <summary>
    /// 
    /// </summary>
    /// <param name="authorizationGrantId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<IReadOnlyCollection<string>> GetGrantConsentedAuthorizationDetails(string authorizationGrantId, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="authorizationGrantId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<IReadOnlyCollection<AuthorizationGrantConsent>> GetGrantConsents(string authorizationGrantId, CancellationToken cancellationToken);
}