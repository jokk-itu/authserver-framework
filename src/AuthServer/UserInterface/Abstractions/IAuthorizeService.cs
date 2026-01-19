using AuthServer.Authorization.Models;
using AuthServer.Endpoints.Responses;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthServer.UserInterface.Abstractions;

public interface IAuthorizeService
{
    Task<SubjectDto> GetSubject(AuthorizeRequestDto authorizeRequestDto, CancellationToken cancellationToken);

    Task<IActionResult> GetErrorResult(string requestUri, string clientId, OAuthError oauthError, HttpContext httpContext, CancellationToken cancellationToken);

    Task<AuthorizeRequestDto?> GetValidatedRequest(string requestUri, string clientId, CancellationToken cancellationToken);
}