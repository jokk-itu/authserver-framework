using AuthServer.Constants;
using Microsoft.AspNetCore.Authorization;

namespace AuthServer.Authorization.OAuthToken;
internal class ScopeRequirementHandler : AuthorizationHandler<ScopeRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ScopeRequirement requirement)
    {
        var scopes = context.User.Claims
            .Where(x => x.Type == ClaimNameConstants.Scope)
            .Select(x => x.Value.Split(' '))
            .SelectMany(x => x)
            .ToList();

        var hasInsufficientScopes = !scopes.Contains(requirement.Scope);

        if (hasInsufficientScopes)
        {
            context.Fail(new AuthorizationFailureReason(this, $"Scope is insufficient. It does not contain {requirement.Scope}"));
        }

        context.Succeed(requirement);
        return Task.CompletedTask;
    }
}