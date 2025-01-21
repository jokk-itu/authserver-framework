using AuthServer.Enums;

namespace AuthServer.Entities;

public class AuthorizationGrantClaimConsent : AuthorizationGrantConsent
{
    public AuthorizationGrantClaimConsent(Consent consent, AuthorizationGrant authorizationGrant)
        : base(consent, authorizationGrant, ConsentType.Claim)
    {
    }
}