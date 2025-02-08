using AuthServer.Authorization;
using AuthServer.Endpoints.Responses;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthServer.Authorize.UserInterface.Abstractions;

public interface IAuthorizeService
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="subjectIdentifier"></param>
    /// <param name="clientId"></param>
    /// <param name="consentedScopes"></param>
    /// <param name="consentedClaims"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task HandleConsent(string subjectIdentifier, string clientId, IReadOnlyCollection<string> consentedScopes, IReadOnlyCollection<string> consentedClaims, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="subjectIdentifier"></param>
    /// <param name="request"></param>
    /// <param name="amr"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task HandleAuthorizationGrant(string subjectIdentifier, AuthorizeRequestDto request, IReadOnlyCollection<string> amr, CancellationToken cancellationToken);

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
    Task<AuthorizeRequestDto?> GetValidatedRequest(string requestUri, string clientId, CancellationToken cancellationToken);

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
    Task<SubjectDto> GetSubject(AuthorizeRequestDto authorizeRequestDto);
}