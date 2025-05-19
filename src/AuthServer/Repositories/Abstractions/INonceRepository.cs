namespace AuthServer.Repositories.Abstractions;
internal interface INonceRepository
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="nonce"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<bool> IsNonceReplay(string nonce, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="clientId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<string?> GetActiveDPoPNonce(string clientId, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="nonce"></param>
    /// <param name="clientId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<bool> IsDPoPNonce(string nonce, string clientId, CancellationToken cancellationToken);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="clientId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<string> CreateDPoPNonce(string clientId, CancellationToken cancellationToken);
}