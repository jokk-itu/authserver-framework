using AuthServer.Enums;

namespace AuthServer.Entities;

public class ScopeConsent : Consent
{
    public ScopeConsent(SubjectIdentifier subjectIdentifier, Client client, Scope scope)
        : base(subjectIdentifier, client, ConsentType.Scope)
    {
        Scope = scope ?? throw new ArgumentNullException(nameof(scope));
    }
    
#pragma warning disable CS8618
    // Used to hydrate EF Core model
    private ScopeConsent() { }
#pragma warning restore
    
    public Scope Scope { get; private init; }
}