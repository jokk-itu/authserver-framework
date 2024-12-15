using AuthServer.Authorization;
using AuthServer.Endpoints.Responses;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthServer.Authorize.Abstractions;

public interface IAuthorizeService
{
    /// <summary>
    /// Creates an AuthorizationGrant entity,
    /// as a proof of authenticating the end-user.
    ///
    /// </summary>
    /// <param name="subjectIdentifier"></param>
    /// <param name="clientId"></param>
    /// <param name="amr"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task CreateAuthorizationGrant(string subjectIdentifier, string clientId, IReadOnlyCollection<string> amr, CancellationToken cancellationToken);
     
    /// <summary>
    /// Creates a ConsentGrant entity or updates an existing one.
    ///
    /// It contains the requested scope and the claims that are consented by the end-user.
    /// </summary>
    /// <param name="subjectIdentifier"></param>
    /// <param name="clientId"></param>
    /// <param name="consentedClaims"></param>
    /// <param name="cancellationToken"></param>
    /// <param name="consentedScope"></param>
    /// <returns></returns>
    Task CreateOrUpdateConsentGrant(string subjectIdentifier, string clientId, IEnumerable<string> consentedScope, IEnumerable<string> consentedClaims, CancellationToken cancellationToken);

    /// <summary>
    /// Get the grant that is consented by the end-user, requested by the client.
    /// </summary>
    /// <param name="subjectIdentifier"></param>
    /// <param name="clientId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<ConsentGrantDto> GetConsentGrantDto(string subjectIdentifier, string clientId, CancellationToken cancellationToken);


    /// <summary>
    /// Get the server persisted AuthorizeRequest.
    /// </summary>
    /// <param name="requestUri"></param>
    /// <param name="clientId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<AuthorizeRequestDto?> GetRequest(string requestUri, string clientId, CancellationToken cancellationToken);

    /// <summary>
    /// Get error result.
    /// </summary>
    /// <param name="requestUri"></param>
    /// <param name="clientId"></param>
    /// <param name="oauthError"></param>
    /// <param name="httpContext"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<IActionResult> GetErrorResult(string requestUri, string clientId, OAuthError oauthError, HttpContext httpContext, CancellationToken cancellationToken);

    /// <summary>
    /// Get the subject from AuthorizeUser, IdTokenHint or AuthenticatedUser.
    /// </summary>
    /// <returns></returns>
    Task<string> GetSubject(AuthorizeRequestDto authorizeRequestDto);
}