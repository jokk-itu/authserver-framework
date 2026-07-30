namespace AuthServer.Authorization.Models;

internal enum TokenAuthorizationValidationError
{
    ConsentNotFound,
    ScopeExceedsConsent,
    ResourceExceedsConsent,
    UnauthorizedClientForScope,
    UnauthorizedResourceForScope
}