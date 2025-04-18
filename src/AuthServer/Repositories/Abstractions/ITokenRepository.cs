using AuthServer.Entities;

namespace AuthServer.Repositories.Abstractions;

internal interface ITokenRepository
{
	/// <summary>
	/// 
	/// </summary>
	/// <param name="registrationAccessToken"></param>
	/// <param name="cancellationToken"></param>
	/// <returns></returns>
	Task<RegistrationToken?> GetActiveRegistrationToken(string registrationAccessToken, CancellationToken cancellationToken);

    /// <summary>
    /// Revokes inactive tokens, based on <paramref name="batchSize"/>.
    /// </summary>
    /// <returns></returns>
    Task RevokeExpiredTokens(int batchSize, CancellationToken cancellationToken);
}