namespace AuthServer.Entities;
public class AuthorizationCodeGrant : AuthorizationGrant
{
    public AuthorizationCodeGrant(Session session, Client client, string subject, AuthenticationContextReference authenticationContextReference)
        : base(session, client, subject, authenticationContextReference)
    {
    }

#pragma warning disable CS8618
    // Used to hydrate EF Core model
    private AuthorizationCodeGrant() { }
#pragma warning restore

    public ICollection<AuthorizationCode> AuthorizationCodes { get; init; } = [];
}