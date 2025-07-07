using AuthServer.Authentication.OAuthToken;
using AuthServer.Constants;
using Microsoft.AspNetCore.Authorization;

namespace AuthServer.Authorization.OAuthToken;
internal class GrantManagementQueryPolicy() : AuthorizationPolicy(
    [new ScopeRequirement(ScopeConstants.GrantManagementQuery)],
    [OAuthTokenAuthenticationDefaults.AuthenticationScheme]);