using AuthServer.Enums;

namespace AuthServer.Entities;
public class AuthorizationGrantNonce : Nonce
{
    public AuthorizationGrantNonce(string value, string hashedValue, AuthorizationGrant authorizationGrant)
        : base(value, hashedValue, NonceType.AuthorizationGrantNonce)
    {
        AuthorizationGrant = authorizationGrant ?? throw new ArgumentNullException(nameof(authorizationGrant));
    }

#pragma warning disable CS8618
    // Used to hydrate EF Core model
    private AuthorizationGrantNonce() { }
#pragma warning restore

    public AuthorizationGrant AuthorizationGrant { get; private init; }
}
