using AuthServer.Enums;

namespace AuthServer.Entities;
public class AuthorizationCode : Code
{
    public AuthorizationCode(AuthorizationCodeGrant authorizationCodeGrant, int expirationSeconds) : base(expirationSeconds, CodeType.AuthorizationCode)
    {
        AuthorizationCodeGrant = authorizationCodeGrant ?? throw new ArgumentNullException(nameof(authorizationCodeGrant));
    }

#pragma warning disable CS8618
    // Used to hydrate EF Core model
    private AuthorizationCode() { }
#pragma warning restore

    public AuthorizationCodeGrant AuthorizationCodeGrant { get; private init; }
}