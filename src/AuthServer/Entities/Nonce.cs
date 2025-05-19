using AuthServer.Core;
using AuthServer.Enums;

namespace AuthServer.Entities;
public abstract class Nonce : Entity<string>
{
    protected Nonce(string value, string hashedValue, NonceType nonceType)
    {
        Id = Guid.NewGuid().ToString();
        Value = string.IsNullOrWhiteSpace(value) ? throw new ArgumentNullException(nameof(value)) : value;
        HashedValue = string.IsNullOrWhiteSpace(hashedValue) ? throw new ArgumentNullException(nameof(hashedValue)) : hashedValue;
        IssuedAt = DateTime.UtcNow;
        NonceType = nonceType;
    }

#pragma warning disable CS8618
    // Used to hydrate EF Core model
    protected Nonce() { }
#pragma warning restore

    public string Value { get; private init; }
    public string HashedValue { get; private init; }
    public DateTime IssuedAt { get; private init; }
    public NonceType NonceType { get; private init; }
}