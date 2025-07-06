// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using AuthServer.Authorization.OAuthToken;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;

namespace AuthServer.Authentication.OAuthToken;

/// <summary>
/// Custom implementation with copy from <see cref="AuthorizationMiddlewareResultHandler"/>.
/// </summary>
public class CustomAuthorizationMiddlewareResultHandler : IAuthorizationMiddlewareResultHandler
{
    /// <inheritdoc />
    public Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy, PolicyAuthorizationResult authorizeResult)
    {
        if (authorizeResult.Succeeded)
        {
            return next(context);
        }

        return Handle();

        async Task Handle()
        {
            if (authorizeResult.Challenged)
            {
                if (policy.AuthenticationSchemes.Count > 0)
                {
                    foreach (var scheme in policy.AuthenticationSchemes)
                    {
                        await context.ChallengeAsync(scheme);
                    }
                }
                else
                {
                    await context.ChallengeAsync();
                }
            }
            else if (authorizeResult.Forbidden)
            {
                if (policy.AuthenticationSchemes.Count > 0)
                {
                    foreach (var scheme in policy.AuthenticationSchemes)
                    {
                        var scopes = authorizeResult.AuthorizationFailure!.FailedRequirements
                            .OfType<ScopeRequirement>()
                            .Select(x => x.Scope)
                            .ToList();

                        await context.ForbidAsync(scheme, new AuthenticationProperties(null, new Dictionary<string, object?>
                        {
                            { OAuthTokenAuthenticationDefaults.ScopeParameter, string.Join(' ', scopes) }
                        }));
                    }
                }
                else
                {
                    await context.ForbidAsync();
                }
            }
        }
    }
}