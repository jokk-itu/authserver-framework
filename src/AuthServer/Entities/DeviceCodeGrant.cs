namespace AuthServer.Entities;
public class DeviceCodeGrant : AuthorizationGrant
{
    public DeviceCodeGrant(Session session, Client client, string subject, AuthenticationContextReference authenticationContextReference)
        : base(session, client, subject, authenticationContextReference)
    {
    }

#pragma warning disable CS8618
    // Used to hydrate EF Core model
    private DeviceCodeGrant() { }
#pragma warning restore

    public ICollection<DeviceCode> DeviceCodes { get; private init; } = [];
}