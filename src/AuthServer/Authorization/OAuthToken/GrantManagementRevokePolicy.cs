using AuthServer.Authentication.OAuthToken;
using AuthServer.Constants;
using Microsoft.AspNetCore.Authorization;

namespace AuthServer.Authorization.OAuthToken;
internal class GrantManagementRevokePolicy() : AuthorizationPolicy(
    [new ScopeRequirement(ScopeConstants.GrantManagementRevoke)],
    [OAuthTokenAuthenticationDefaults.AuthenticationScheme]);
