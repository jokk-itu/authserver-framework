﻿using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Endpoints.Responses;
using AuthServer.Options;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using AuthServer.Endpoints.Abstractions;
using AuthServer.Enums;
using AuthServer.Extensions;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest.EndpointBuilders;

public class RegisterEndpointBuilder : EndpointBuilder<RegisterEndpointBuilder>
{
    private Dictionary<string, object> _registerParameters = [];

    public RegisterEndpointBuilder(
        HttpClient httpClient,
        DiscoveryDocument discoveryDocument,
        JwksDocument jwksDocument,
        IEndpointResolver endpointResolver,
        ITestOutputHelper testOutputHelper)
        : base(httpClient, discoveryDocument, jwksDocument, endpointResolver, testOutputHelper)
    {
    }

    public RegisterEndpointBuilder WithUserinfoSignedResponseAlg(SigningAlg signingAlg)
    {
        _registerParameters.Add(Parameter.UserinfoSignedResponseAlg, signingAlg.GetDescription());
        return this;
    }

    public RegisterEndpointBuilder WithRequestUriExpiration(int expiration)
    {
        _registerParameters.Add(Parameter.RequestUriExpiration, expiration);
        return this;
    }

    public RegisterEndpointBuilder WithScope(IReadOnlyCollection<string> scope)
    {
        _registerParameters.Add(Parameter.Scope, string.Join(' ', scope));
        return this;
    }

    public RegisterEndpointBuilder WithClientName(string clientName)
    {
        _registerParameters.Add(Parameter.ClientName, clientName);
        return this;
    }

    public RegisterEndpointBuilder WithGrantTypes(IReadOnlyCollection<string> grantTypes)
    {
        _registerParameters.Add(Parameter.GrantTypes, grantTypes);
        return this;
    }

    public RegisterEndpointBuilder WithRedirectUris(IReadOnlyCollection<string> redirectUris)
    {
        _registerParameters.Add(Parameter.RedirectUris, redirectUris);
        return this;
    }

    public RegisterEndpointBuilder WithTokenEndpointAuthMethod(TokenEndpointAuthMethod tokenEndpointAuthMethod)
    {
        _registerParameters.Add(Parameter.TokenEndpointAuthMethod, tokenEndpointAuthMethod.GetDescription());
        return this;
    }

    public RegisterEndpointBuilder WithJwks(string jwks)
    {
        _registerParameters.Add(Parameter.Jwks, jwks);
        return this;
    }

    public RegisterEndpointBuilder WithRequestObjectSigningAlg(SigningAlg requestObjectSigningAlg)
    {
        _registerParameters.Add(Parameter.RequestObjectSigningAlg, requestObjectSigningAlg.GetDescription());
        return this;
    }

    public RegisterEndpointBuilder WithRequireReferenceToken()
    {
        _registerParameters.Add(Parameter.RequireReferenceToken, true);
        return this;
    }

    public RegisterEndpointBuilder WithPostLogoutRedirectUris(IReadOnlyCollection<string> postLogoutRedirectUris)
    {
        _registerParameters.Add(Parameter.PostLogoutRedirectUris, postLogoutRedirectUris);
        return this;
    }

    internal async Task<RegisterResponse> Post()
    {
        var json = JsonSerializer.Serialize(_registerParameters);
        var httpRequestMessage = new HttpRequestMessage(HttpMethod.Post, "connect/register")
        {
            Content = new StringContent(json, Encoding.UTF8, MimeTypeConstants.Json)
        };
        var httpResponseMessage = await HttpClient.SendAsync(httpRequestMessage);

        TestOutputHelper.WriteLine(
            "Received Register response {0}, Content: {1}",
            httpResponseMessage.StatusCode,
            await httpResponseMessage.Content.ReadAsStringAsync());

        httpResponseMessage.EnsureSuccessStatusCode();
        return (await httpResponseMessage.Content.ReadFromJsonAsync<RegisterResponse>())!;
    }
}
