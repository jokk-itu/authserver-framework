namespace AuthServer.TokenDecoders;
public enum ClientTokenAudience
{
    TokenEndpoint,
    AuthorizationEndpoint,
    IntrospectionEndpoint,
    RevocationEndpoint,
    PushedAuthorizationEndpoint,
    UserinfoEndpoint,
    GrantManagementEndpoint,
    DeviceAuthorizationEndpoint
}