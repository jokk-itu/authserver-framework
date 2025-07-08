using AuthServer.Core;
using System.Linq.Expressions;
using AuthServer.Enums;

namespace AuthServer.Entities;
public abstract class Code : Entity<string>
{
    protected Code(int expirationSeconds, CodeType codeType)
    {
        Id = Guid.NewGuid().ToString();
        IssuedAt = DateTime.UtcNow;
        ExpiresAt = IssuedAt.AddSeconds(expirationSeconds);
        CodeType = codeType;
    }

#pragma warning disable CS8618
    // Used to hydrate EF Core model
    protected Code() { }
#pragma warning restore

    public string RawValue { get; private set; } = null!;
    public DateTime IssuedAt { get; private init; }
    public DateTime ExpiresAt { get; private init; }
    public DateTime? RedeemedAt { get; private set; }
    public CodeType CodeType { get; private init; }

    public static readonly Expression<Func<AuthorizationCode, bool>> IsActive =
        x => x.RedeemedAt == null && x.ExpiresAt > DateTime.UtcNow;

    public void Redeem()
    {
        RedeemedAt ??= DateTime.UtcNow;
    }

    public void SetRawValue(string value)
    {
        RawValue = value;
    }
}