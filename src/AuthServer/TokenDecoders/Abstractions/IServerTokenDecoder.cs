namespace AuthServer.TokenDecoders.Abstractions;
internal interface IServerTokenDecoder
{
    /// <summary>
    /// Reads the token, and does not validate it.
    /// It throws if the token cannot be read.
    /// </summary>
    /// <exception cref=""></exception>
    /// <param name="token"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<TokenResult> Read(string token, CancellationToken cancellationToken);

    /// <summary>
    /// Reads and validates the token, based on the <paramref name="arguments"/>.
    /// It returns null if validation fails, and does not throw.
    /// </summary>
    /// <param name="token"></param>
    /// <param name="arguments"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<TokenResult?> Validate(string token, ServerTokenDecodeArguments arguments, CancellationToken cancellationToken);
}