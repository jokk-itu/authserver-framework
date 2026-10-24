using AuthServer.Authorization.Models;

namespace AuthServer.Authorization.Abstractions;

public interface IAuthorizationDetailValidator
{
    /// <summary>
    /// Validates an authorization_detail entity from the authorization_details parameter during authorization.
    /// </summary>
    /// <param name="authorizationDetail">A JSON encoded AuthorizationDetail</param>
    /// <param name="cancellationToken"></param>
    /// <returns>The validated AuthorizationDetail, or null if invalid.</returns>
    Task<AuthorizationDetailDto?> ValidateAuthorizationDetail(string authorizationDetail, CancellationToken cancellationToken);

    /// <summary>
    /// Validates an authorization_detail entity from the authorization_details parameter during token,
    /// and compare against previously consented authorization details.
    /// </summary>
    /// <param name="authorizationDetail"></param>
    /// <param name="grantAuthorizationDetails"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<bool> ValidateAuthorizationDetail(string authorizationDetail, IReadOnlyCollection<string> grantAuthorizationDetails, CancellationToken cancellationToken);
}