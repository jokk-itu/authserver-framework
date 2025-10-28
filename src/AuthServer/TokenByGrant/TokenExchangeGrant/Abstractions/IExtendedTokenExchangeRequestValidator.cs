using AuthServer.Endpoints.Responses;

namespace AuthServer.TokenByGrant.TokenExchangeGrant.Abstractions;
public interface IExtendedTokenExchangeRequestValidator
{
    /// <summary>
    /// Further validate the request using your own custom rules.
    /// </summary>
    /// <param name="validatedRequest"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<OAuthError?> Validate(ValidatedTokenExchangeRequest validatedRequest, CancellationToken cancellationToken);
}