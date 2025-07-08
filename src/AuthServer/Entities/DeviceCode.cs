using AuthServer.Enums;

namespace AuthServer.Entities;
public class DeviceCode : Code
{
    public DeviceCode(int expirationSeconds, int currentInterval) : base(expirationSeconds, CodeType.DeviceCode)
    {
        CurrentInterval = currentInterval;
    }

#pragma warning disable CS8618
    // Used to hydrate EF Core model
    private DeviceCode() { }
#pragma warning restore

    public DateTime? LatestPoll { get; private set; }
    public int CurrentInterval { get; private set; }
    public DeviceCodeGrant? DeviceCodeGrant { get; private set; }

    public void UpdatePoll(int interval)
    {
        LatestPoll = DateTime.UtcNow;
        CurrentInterval = interval;
    }
}