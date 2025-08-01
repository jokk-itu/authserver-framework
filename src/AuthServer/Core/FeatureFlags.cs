namespace AuthServer.Core;

public static class FeatureFlags
{
    public const string PushedAuthorization = "PushedAuthorization";
    public const string EndSession = "EndSession";
    public const string Discovery = "Discovery";
    public const string Jwks = "Jwks";
    public const string GrantManagementQuery = "GrantManagementQuery";
    public const string GrantManagementRevoke = "GrantManagementRevoke";
    public const string Authorize = "Authorize";
    public const string RefreshToken = "RefreshToken";
    public const string AuthorizationCode = "AuthorizationCode";
    public const string ClientCredentials = "ClientCredentials";
    public const string TokenRevocation = "TokenRevocation";
    public const string TokenIntrospection = "TokenIntrospection";
    public const string RegisterDelete = "RegisterDelete";
    public const string RegisterGet = "RegisterGet";
    public const string RegisterPut = "RegisterPut";
    public const string RegisterPost = "RegisterPost";
    public const string Userinfo = "Userinfo";
    public const string DeviceAuthorization = "DeviceAuthorization";
    public const string DeviceCode = "DeviceCode";
    public const string TokenExchange = "TokenExchange";
}