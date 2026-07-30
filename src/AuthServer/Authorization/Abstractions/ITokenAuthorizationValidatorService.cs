using AuthServer.Authorization.Models;

namespace AuthServer.Authorization.Abstractions;

internal interface ITokenAuthorizationValidatorService
{
    /// <summary>
    /// Validates token authorization parameters Scopes, Resources and AuthorizationDetails for a grant.
    /// </summary>
    /// <param name="validationDto"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<TokenAuthorizationValidationResult> ValidateTokenAuthorizationGrant(TokenAuthorizationGrantValidationDto validationDto, CancellationToken cancellationToken);

    /// <summary>
    /// Validates token authorization parameters Scopes, Resources and AuthorizationDetails for a client.
    /// </summary>
    /// <param name="validationDto"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<TokenAuthorizationValidationResult> ValidateTokenAuthorizationClient(TokenAuthorizationClientValidationDto validationDto, CancellationToken cancellationToken);
}