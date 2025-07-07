using AuthServer.Authentication.OAuthToken;
using AuthServer.Constants;
using Microsoft.AspNetCore.Authorization;

namespace AuthServer.Authorization.OAuthToken;
internal class RegisterPolicy() : AuthorizationPolicy([new ScopeRequirement(ScopeConstants.Register)],
    [OAuthTokenAuthenticationDefaults.AuthenticationScheme]);