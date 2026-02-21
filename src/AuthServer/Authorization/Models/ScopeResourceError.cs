namespace AuthServer.Authorization.Models;

internal enum ScopeResourceError
{
    ConsentNotFound,
    ScopeExceedsConsent,
    ResourceExceedsConsent,
    UnauthorizedClientForScope,
    UnauthorizedResourceForScope
}