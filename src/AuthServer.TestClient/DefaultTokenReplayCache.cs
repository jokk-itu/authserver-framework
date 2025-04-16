using Microsoft.IdentityModel.Tokens;

namespace AuthServer.TestClient;

public class DefaultTokenReplayCache : ITokenReplayCache
{
    private readonly IDictionary<string, DateTime> _cache = new Dictionary<string, DateTime>();

    public bool TryAdd(string securityToken, DateTime expiresOn) => _cache.TryAdd(securityToken, expiresOn);
    public bool TryFind(string securityToken) => _cache.ContainsKey(securityToken);
}
