using Microsoft.IdentityModel.JsonWebTokens;

namespace AuthServer.TokenDecoders.Abstractions;
internal interface IClientTokenDecoder
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="token"></param>
    /// <returns></returns>
    Task<JsonWebToken> Read(string token);

    /// <summary>
    /// 
    /// </summary>
    /// <param name="token"></param>
    /// <param name="arguments"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task<JsonWebToken?> Validate(string token, ClientTokenDecodeArguments arguments, CancellationToken cancellationToken);
}