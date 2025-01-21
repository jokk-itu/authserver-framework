using AuthServer.Enums;

namespace AuthServer.Entities;

public class ScopeConsent : Consent
{
    public ScopeConsent(SubjectIdentifier subjectIdentifier, Client client, Scope scope)
        : base(subjectIdentifier, client, ConsentType.Scope)
    {
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));
    }
    
    public Scope Scope { get; private init; }
}