using AuthServer.Enums;

namespace AuthServer.Entities;
public class DeviceCode : Code
{
    public DeviceCode(int expirationSeconds, int currentInterval) : base(expirationSeconds, CodeType.DeviceCode)
    {
        CurrentInterval = currentInterval < 0
            ? throw new ArgumentException("must not be a negative number", nameof(currentInterval))
            : currentInterval;
    }

#pragma warning disable CS8618
    // Used to hydrate EF Core model
    private DeviceCode() { }
#pragma warning restore

    public DateTime? LatestPoll { get; private set; }
    public int CurrentInterval { get; private set; }
    public DeviceCodeGrant? DeviceCodeGrant { get; private set; }
    public DateTime? RevokedAt { get; private set; }

    public void IncrementInterval(int interval)
    {
        UpdatePoll();
        CurrentInterval += interval;
    }

    public void UpdatePoll()
    {
        LatestPoll = DateTime.UtcNow;
    }

    public void Revoke()
    {
        RevokedAt ??= DateTime.UtcNow;
    }

    public bool IsWithinInterval() =>
        LatestPoll is null || LatestPoll.Value.AddSeconds(CurrentInterval) < DateTime.UtcNow;
}