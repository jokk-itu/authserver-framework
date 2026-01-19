namespace AuthServer.Repositories.Abstractions;

internal interface ITokenRepository
{
    /// <summary>
    /// Revokes inactive tokens, based on <paramref name="batchSize"/>.
    /// </summary>
    /// <returns></returns>
    Task RevokeExpiredTokens(int batchSize, CancellationToken cancellationToken);
}