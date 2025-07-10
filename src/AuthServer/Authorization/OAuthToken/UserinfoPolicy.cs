using AuthServer.Authentication.OAuthToken;
using AuthServer.Constants;
using Microsoft.AspNetCore.Authorization;

namespace AuthServer.Authorization.OAuthToken;
internal class UserinfoPolicy() : AuthorizationPolicy([new ScopeRequirement(ScopeConstants.UserInfo)],
    [OAuthTokenAuthenticationDefaults.AuthenticationScheme]);