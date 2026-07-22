using AuthServer.Enums;

namespace AuthServer.Entities;

public class AuthorizationGrantAuthorizationDetailTypeConsent : AuthorizationGrantConsent
{
    public AuthorizationGrantAuthorizationDetailTypeConsent(Consent consent, AuthorizationGrant authorizationGrant, string rawValue)
        : base(consent, authorizationGrant, ConsentType.AuthorizationDetailType)
    {
        RawValue = rawValue;
    }

#pragma warning disable CS8618
    // Used to hydrate EF Core model
    private AuthorizationGrantAuthorizationDetailTypeConsent() { }
#pragma warning restore

    public string RawValue { get; private init; }
}