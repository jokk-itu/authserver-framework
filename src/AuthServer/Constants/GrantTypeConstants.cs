namespace AuthServer.Constants;
public static class GrantTypeConstants
{
    public const string AuthorizationCode = "authorization_code";
    public const string RefreshToken = "refresh_token";
    public const string ClientCredentials = "client_credentials";
    public const string DeviceCode = "urn:ietf:params:oauth:grant-type:device_code";

    public static readonly string[] GrantTypes = [AuthorizationCode, RefreshToken, ClientCredentials, DeviceCode];
}