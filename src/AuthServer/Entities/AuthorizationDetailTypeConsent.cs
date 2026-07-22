using AuthServer.Enums;

namespace AuthServer.Entities;

public class AuthorizationDetailTypeConsent : Consent
{
    public AuthorizationDetailTypeConsent(SubjectIdentifier subjectIdentifier, Client client, AuthorizationDetailType authorizationDetailType)
        : base(subjectIdentifier, client, ConsentType.AuthorizationDetailType)
    {
        AuthorizationDetailType = authorizationDetailType ?? throw new ArgumentNullException(nameof(authorizationDetailType));
    }

#pragma warning disable CS8618
    // Used to hydrate EF Core model
    private AuthorizationDetailTypeConsent() { }
#pragma warning restore

    public AuthorizationDetailType AuthorizationDetailType { get; private init; }
}