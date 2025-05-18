using System.Linq.Expressions;
using AuthServer.Enums;

namespace AuthServer.Entities;
public class DPoPNonce : Nonce
{
    public DPoPNonce(string value, string hashedValue, Client client)
        : base(value, hashedValue, NonceType.AuthorizationGrantNonce)
    {
        Client = client ?? throw new ArgumentNullException(nameof(client));
        ExpiresAt = IssuedAt.AddSeconds(Client.DPoPNonceExpiration);
    }

#pragma warning disable CS8618
    // Used to hydrate EF Core model
    private DPoPNonce() { }
#pragma warning restore

    public DateTime ExpiresAt { get; private init; }
    public Client Client { get; private init; }

    public static readonly Expression<Func<DPoPNonce, bool>> IsActive =
        x => x.ExpiresAt > DateTime.UtcNow;
}