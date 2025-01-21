using AuthServer.Enums;

namespace AuthServer.Entities;

public class AuthorizationGrantScopeConsent : AuthorizationGrantConsent
{
    public AuthorizationGrantScopeConsent(Consent consent, AuthorizationGrant authorizationGrant, string resource)
        : base(consent, authorizationGrant, ConsentType.Scope)
    {
        Resource = resource;
    }
    
    public AuthorizationGrantScopeConsent(Consent consent, AuthorizationGrant authorizationGrant)
        : base(consent, authorizationGrant, ConsentType.Scope)
    {}
    
    public string? Resource { get; private init; }
}