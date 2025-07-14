using AuthServer.Core;

namespace AuthServer.Entities;
public class UserCode : Entity<string>
{
    public UserCode(DeviceCode deviceCode, string value)
    {
        Id = Guid.NewGuid().ToString();
        Value = value;
        DeviceCode = deviceCode ?? throw new ArgumentNullException(nameof(deviceCode));
    }

#pragma warning disable CS8618
    // Used to hydrate EF Core model
    private UserCode() { }
#pragma warning restore

    public string Value { get; private init; }
    public DateTime? RedeemedAt { get; private set; }
    public DeviceCode DeviceCode { get; private init; }

    public void Redeem()
    {
        RedeemedAt ??= DateTime.UtcNow;
    }
}