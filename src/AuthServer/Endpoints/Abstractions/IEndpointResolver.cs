namespace AuthServer.Endpoints.Abstractions;

public interface IEndpointResolver
{
    string AuthorizationEndpoint { get; }
    string TokenEndpoint { get; }
    string UserinfoEndpoint { get; }
    string JwksEndpoint { get; }
    string RegistrationEndpoint { get; }
    string EndSessionEndpoint { get; }
    string IntrospectionEndpoint { get; }
    string RevocationEndpoint { get; }
    string PushedAuthorizationEndpoint { get; }
    string GrantManagementEndpoint { get; }
}