using Microsoft.AspNetCore.Authentication;

namespace AuthServer.TestClient;

public sealed class OpenIdConnectEvents : RemoteAuthenticationEvents
{
    public Func<RedirectContext, Task> OnRedirectToIdentityProviderForChallenge { get; set; } =
        _ => Task.CompletedTask;
    
    public Task RedirectToIdentityProviderForChallenge(RedirectContext redirectContext)
        => OnRedirectToIdentityProviderForChallenge(redirectContext);
}