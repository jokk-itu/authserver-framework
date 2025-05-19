using AuthServer.Authorization.Models;

namespace AuthServer.Authorization.Abstractions;
internal interface IDPoPService
{
    /// <summary>
    /// Validate the DPoP.
    /// </summary>
    /// <param name="dPoP"></param>
    /// <param name="clientId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns>validation result dictating if the DPoP is valid or not.</returns>
    Task<DPoPValidationResult> ValidateDPoP(string dPoP, string clientId, CancellationToken cancellationToken);
}
