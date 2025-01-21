using AuthServer.Core;
using AuthServer.Enums;

namespace AuthServer.Entities;
public abstract class Consent : Entity<int>
{
    protected Consent(SubjectIdentifier subjectIdentifier, Client client, ConsentType consentType)
    {
        SubjectIdentifier = subjectIdentifier ?? throw new ArgumentNullException(nameof(subjectIdentifier));
        Client = client ?? throw new ArgumentNullException(nameof(client));
        ConsentType = consentType;
    }

#pragma warning disable CS8618
    // Used to hydrate EF Core model
    protected Consent() { }
#pragma warning restore

    public ConsentType ConsentType { get; private set; }
    public Client Client { get; private init; }
    public SubjectIdentifier SubjectIdentifier { get; private init; }
    public ICollection<AuthorizationGrantConsent> AuthorizationGrantConsents { get; private init; } = [];
}