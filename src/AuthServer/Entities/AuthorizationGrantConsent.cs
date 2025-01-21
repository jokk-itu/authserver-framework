using AuthServer.Core;
using AuthServer.Enums;

namespace AuthServer.Entities;

public abstract class AuthorizationGrantConsent : Entity<int>
{
    protected AuthorizationGrantConsent(Consent consent, AuthorizationGrant authorizationGrant, ConsentType consentType)
    {
        Consent = consent ?? throw new ArgumentNullException(nameof(consent));
        AuthorizationGrant = authorizationGrant ?? throw new ArgumentNullException(nameof(authorizationGrant));
        ConsentType = consentType;
    }
    
#pragma warning disable CS8618
    // Used to hydrate EF Core model
    private AuthorizationGrantConsent() { }
#pragma warning restore
        
    public Consent Consent { get; private init; }
    public AuthorizationGrant AuthorizationGrant { get; private init; }
    public ConsentType ConsentType { get; private init; }
}