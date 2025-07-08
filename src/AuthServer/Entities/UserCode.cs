using AuthServer.Enums;

namespace AuthServer.Entities;
public class UserCode : Code
{
    public UserCode(DeviceCode deviceCode, string value, int expirationSeconds) : base(expirationSeconds, CodeType.UserCode)
    {
        Value = value;
        SetRawValue(value);
        DeviceCode = deviceCode ?? throw new ArgumentNullException(nameof(deviceCode));
    }

#pragma warning disable CS8618
    // Used to hydrate EF Core model
    private UserCode() { }
#pragma warning restore

    public string Value { get; private init; }
    public DeviceCode DeviceCode { get; private init; }
}