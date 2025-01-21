using AuthServer.Enums;

namespace AuthServer.Entities;

public class ClaimConsent : Consent
{
    public ClaimConsent(SubjectIdentifier subjectIdentifier, Client client, Claim claim)
        : base(subjectIdentifier, client, ConsentType.Claim)
    {
        Claim = claim ?? throw new ArgumentNullException(nameof(claim));
    }
    
    public Claim Claim { get; private init; }
}