using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Helpers;
using AuthServer.Repositories.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.Repositories;
internal class NonceRepository : INonceRepository
{
    private readonly AuthorizationDbContext _authorizationDbContext;

    public NonceRepository(AuthorizationDbContext authorizationDbContext)
    {
        _authorizationDbContext = authorizationDbContext;
    }

    /// <inheritdoc/>
    public async Task<bool> IsNonceReplay(string nonce, CancellationToken cancellationToken)
    {
        var hashedNonce = nonce.Sha256();
        return await _authorizationDbContext
            .Set<Nonce>()
            .AnyAsync(x => x.HashedValue == hashedNonce, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<bool> IsActiveDPoPNonce(string nonce, string clientId, CancellationToken cancellationToken)
    {
        var hashedNonce = nonce.Sha256();
        return await _authorizationDbContext
            .Set<DPoPNonce>()
            .Where(x => x.HashedValue == hashedNonce)
            .Where(x => x.Client.Id == clientId)
            .Where(DPoPNonce.IsActive)
            .AnyAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<string> CreateDPoPNonce(string clientId, CancellationToken cancellationToken)
    {
        var client = (await _authorizationDbContext.Set<Client>().FindAsync([clientId], cancellationToken))!;
        var nonce = CryptographyHelper.GetRandomString(32);
        var dDPoPNonce = new DPoPNonce(nonce, nonce.Sha256(), client);
        client.Nonces.Add(dDPoPNonce);
        await _authorizationDbContext.SaveChangesAsync(cancellationToken);
        return nonce;
    }
}
