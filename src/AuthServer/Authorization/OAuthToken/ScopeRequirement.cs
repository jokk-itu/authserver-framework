using Microsoft.AspNetCore.Authorization;

namespace AuthServer.Authorization.OAuthToken;

internal record ScopeRequirement(string Scope) : IAuthorizationRequirement;