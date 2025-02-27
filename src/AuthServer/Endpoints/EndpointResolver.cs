using AuthServer.Endpoints.Abstractions;
using AuthServer.Options;
using Microsoft.Extensions.Options;

namespace AuthServer.Endpoints;

internal class EndpointResolver : IEndpointResolver
{
    public string AuthorizationEndpoint { get; }
    public string TokenEndpoint { get; }
    public string UserinfoEndpoint { get; }
    public string JwksEndpoint { get; }
    public string DiscoveryEndpoint { get; }
    public string RegistrationEndpoint { get; }
    public string EndSessionEndpoint { get; }
    public string IntrospectionEndpoint { get; }
    public string RevocationEndpoint { get; }
    public string PushedAuthorizationEndpoint { get; }
    public string GrantManagementEndpoint { get; }

    public EndpointResolver(IOptionsSnapshot<DiscoveryDocument> discoveryDocumentOptions)
    {
        var issuer = discoveryDocumentOptions.Value.Issuer;
        AuthorizationEndpoint = $"{issuer}/connect/authorize";
        TokenEndpoint = $"{issuer}/connect/token";
        UserinfoEndpoint = $"{issuer}/connect/userinfo";
        JwksEndpoint = $"{issuer}/.well-known/jwks";
        DiscoveryEndpoint = $"{issuer}/.well-known/openid-configuration";
        RegistrationEndpoint = $"{issuer}/connect/register";
        EndSessionEndpoint = $"{issuer}/connect/end-session";
        IntrospectionEndpoint = $"{issuer}/connect/introspection";
        RevocationEndpoint = $"{issuer}/connect/revoke";
        PushedAuthorizationEndpoint = $"{issuer}/connect/par";
        GrantManagementEndpoint = $"{issuer}/connect/grants";
    }
}