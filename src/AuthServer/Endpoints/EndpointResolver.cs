using AuthServer.Endpoints.Abstractions;
using AuthServer.Options;
using AuthServer.TokenDecoders;
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

    public string Convert(ClientTokenAudience clientTokenAudience)
    {
        return clientTokenAudience switch
        {
            ClientTokenAudience.AuthorizationEndpoint => AuthorizationEndpoint,
            ClientTokenAudience.TokenEndpoint => TokenEndpoint,
            ClientTokenAudience.UserinfoEndpoint => UserinfoEndpoint,
            ClientTokenAudience.IntrospectionEndpoint => IntrospectionEndpoint,
            ClientTokenAudience.RevocationEndpoint => RevocationEndpoint,
            ClientTokenAudience.PushedAuthorizationEndpoint => PushedAuthorizationEndpoint,
            ClientTokenAudience.GrantManagementEndpoint => GrantManagementEndpoint,
            _ => throw new ArgumentException("is not mappable to an endpoint", nameof(clientTokenAudience))
        };
    }

    public ClientTokenAudience Convert(string endpoint)
    {
        if (endpoint == AuthorizationEndpoint)
        {
            return ClientTokenAudience.AuthorizationEndpoint;
        }

        if (endpoint == TokenEndpoint)
        {
            return ClientTokenAudience.TokenEndpoint;
        }

        if (endpoint == UserinfoEndpoint)
        {
            return ClientTokenAudience.UserinfoEndpoint;
        }

        if (endpoint == IntrospectionEndpoint)
        {
            return ClientTokenAudience.IntrospectionEndpoint;
        }

        if (endpoint == RevocationEndpoint)
        {
            return ClientTokenAudience.RevocationEndpoint;
        }

        if (endpoint == PushedAuthorizationEndpoint)
        {
            return ClientTokenAudience.PushedAuthorizationEndpoint;
        }

        if (endpoint == GrantManagementEndpoint)
        {
            return ClientTokenAudience.GrantManagementEndpoint;
        }

        throw new InvalidOperationException($"Endpoint {endpoint} is unrecognizable");
    }
}