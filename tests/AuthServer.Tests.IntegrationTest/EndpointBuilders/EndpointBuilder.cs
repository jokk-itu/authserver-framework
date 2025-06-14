using AuthServer.Constants;
using AuthServer.Endpoints.Abstractions;
using AuthServer.Options;
using AuthServer.Tests.Core;
using Microsoft.IdentityModel.Tokens;
using AuthServer.Core;
using Xunit.Abstractions;
using static AuthServer.Tests.Core.ClientJwkBuilder;

namespace AuthServer.Tests.IntegrationTest.EndpointBuilders;
public abstract class EndpointBuilder<TEndpointBuilder>
    where TEndpointBuilder : EndpointBuilder<TEndpointBuilder>
{
    protected readonly DiscoveryDocument DiscoveryDocument;
    protected readonly JwksDocument JwksDocument;
    protected readonly HttpClient HttpClient;
    protected readonly ITestOutputHelper TestOutputHelper;
    protected readonly JwtBuilder JwtBuilder;
    protected readonly IEndpointResolver EndpointResolver;

    protected ClientJwks? ClientJwks;
    protected List<KeyValuePair<string, string>> _parameters = [];

    private bool _isDPoPProtected;
    private string? _dPoPNonce;
    private bool _isDPoPJktProtected;

    protected EndpointBuilder(
        HttpClient httpClient,
        DiscoveryDocument discoveryDocument,
        JwksDocument jwksDocument,
        IEndpointResolver endpointResolver,
        ITestOutputHelper testOutputHelper)
    {
        DiscoveryDocument = discoveryDocument;
        JwksDocument = jwksDocument;
        HttpClient = httpClient;
        TestOutputHelper = testOutputHelper;
        EndpointResolver = endpointResolver;
        JwtBuilder = new JwtBuilder(discoveryDocument, jwksDocument, endpointResolver);
    }

    public TEndpointBuilder WithDPoP(string? dPoPNonce)
    {
        _isDPoPProtected = true;
        _dPoPNonce = dPoPNonce;
        return (TEndpointBuilder)this;
    }

    public TEndpointBuilder WithDPoPJkt()
    {
        _isDPoPJktProtected = true;
        return (TEndpointBuilder)this;
    }

    public TEndpointBuilder WithClientJwks(ClientJwks clientJwks)
    {
        ClientJwks = clientJwks;
        return (TEndpointBuilder)this;
    }

    protected void AddDPoP(HttpRequestMessage httpRequestMessage, string endpoint)
    {
        if (!_isDPoPProtected && !_isDPoPJktProtected)
        {
            return;
        }

        var uri = $"{HttpClient.BaseAddress}{endpoint}";

        var claims = new Dictionary<string, object>
        {
            { ClaimNameConstants.Htm, httpRequestMessage.Method.Method },
            { ClaimNameConstants.Htu, uri }
        };

        if (_dPoPNonce is not null)
        {
            claims.Add(ClaimNameConstants.Nonce, _dPoPNonce);
        }

        var dPoP = JwtBuilder.GetDPoPToken(
            claims,
            _parameters.Single(x => x.Key == Parameter.ClientId).Value.ToString()!,
            ClientJwks!,
            EndpointResolver.Convert(uri));

        if (_isDPoPProtected)
        {
            httpRequestMessage.Headers.Add(Parameter.DPoP, dPoP);
        }

        if (_isDPoPJktProtected)
        {
            var jsonWebKey = new JsonWebKeySet(ClientJwks!.PublicJwks).Keys.Single(x => x.Use == JsonWebKeyUseNames.Sig);
            var dPoPJkt = Base64UrlEncoder.Encode(jsonWebKey.ComputeJwkThumbprint());
            _parameters.Add(new KeyValuePair<string, string>(Parameter.DPoPJkt, dPoPJkt));
        }
    }
}
