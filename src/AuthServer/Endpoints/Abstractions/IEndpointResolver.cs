using AuthServer.TokenDecoders;

namespace AuthServer.Endpoints.Abstractions;

public interface IEndpointResolver
{
    string AuthorizationEndpoint { get; }
    string TokenEndpoint { get; }
    string UserinfoEndpoint { get; }
    string JwksEndpoint { get; }
    string DiscoveryEndpoint { get; }
    string RegistrationEndpoint { get; }
    string EndSessionEndpoint { get; }
    string IntrospectionEndpoint { get; }
    string RevocationEndpoint { get; }
    string PushedAuthorizationEndpoint { get; }
    string GrantManagementEndpoint { get; }
    string DeviceAuthorizationEndpoint { get; }

    string Convert(ClientTokenAudience clientTokenAudience);
    ClientTokenAudience Convert(string endpoint);
}