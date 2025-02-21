using AuthServer.Enums;

namespace AuthServer.Entities;

public class AuthorizationGrantScopeConsent : AuthorizationGrantConsent
{
    public AuthorizationGrantScopeConsent(Consent consent, AuthorizationGrant authorizationGrant, string resource)
        : base(consent, authorizationGrant, ConsentType.Scope)
    {
        Resource = resource;
    }
    
#pragma warning disable CS8618
    // Used to hydrate EF Core model
    private AuthorizationGrantScopeConsent() { }
#pragma warning restore
    
    public string Resource { get; private init; }
}