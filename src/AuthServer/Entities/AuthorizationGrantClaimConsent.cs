using AuthServer.Enums;

namespace AuthServer.Entities;

public class AuthorizationGrantClaimConsent : AuthorizationGrantConsent
{
    public AuthorizationGrantClaimConsent(Consent consent, AuthorizationGrant authorizationGrant)
        : base(consent, authorizationGrant, ConsentType.Claim)
    {
    }
    
#pragma warning disable CS8618
    // Used to hydrate EF Core model
    private AuthorizationGrantClaimConsent() { }
#pragma warning restore
}