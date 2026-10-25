using AuthServer.Authorization.Models;

namespace AuthServer.Authorization.Abstractions;

internal interface IAuthorizationDetailsValidator
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="authorizationDetails"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<AuthorizationDetailsValidationResult> ValidateAuthorizationDetails(string? authorizationDetails, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="authorizationDetails"></param>
    /// <param name="clientId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<AuthorizationDetailsValidationResult> AuthorizeAuthorizationDetails(string? authorizationDetails, string clientId, CancellationToken cancellationToken);
}