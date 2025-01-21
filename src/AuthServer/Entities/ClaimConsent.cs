using AuthServer.Enums;

namespace AuthServer.Entities;

public class ClaimConsent : Consent
{
    public ClaimConsent(SubjectIdentifier subjectIdentifier, Client client, Claim claim)
        : base(subjectIdentifier, client, ConsentType.Claim)
    {
        Claim = claim ?? throw new ArgumentNullException(nameof(claim));
    }
    
#pragma warning disable CS8618
    // Used to hydrate EF Core model
    private ClaimConsent() { }
#pragma warning restore
    
    public Claim Claim { get; private init; }
}