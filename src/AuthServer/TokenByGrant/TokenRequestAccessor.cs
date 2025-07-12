using AuthServer.Authentication.Models;
using AuthServer.Core;
using Microsoft.AspNetCore.Http;
using AuthServer.Extensions;
using AuthServer.TokenDecoders;
using AuthServer.Core.Abstractions;

namespace AuthServer.TokenByGrant;

internal class TokenRequestAccessor : IRequestAccessor<TokenRequest>
{
    public async Task<TokenRequest> GetRequest(HttpRequest httpRequest)
    {
        var dPoP = httpRequest.Headers.GetValue(Parameter.DPoP);

        var body = await httpRequest.ReadFormAsync();

        var grantType = body.GetValue(Parameter.GrantType);
        var deviceCode = body.GetValue(Parameter.DeviceCode);
        var code = body.GetValue(Parameter.Code);
        var codeVerifier = body.GetValue(Parameter.CodeVerifier);
        var redirectUri = body.GetValue(Parameter.RedirectUri);
        var refreshToken = body.GetValue(Parameter.RefreshToken);

        var scope = body.GetSpaceDelimitedValue(Parameter.Scope);
        var resource = body.GetCollectionValue(Parameter.Resource);

        var clientSecretBasic = httpRequest.GetClientSecretBasic();
        var clientSecretPost = body.GetClientSecretPost();
        var clientAssertion = body.GetClientAssertion(ClientTokenAudience.TokenEndpoint);
        var clientId = body.GetClientId();

        var clientAuthentications = new List<ClientAuthentication>();
        if (clientSecretBasic is not null) clientAuthentications.Add(clientSecretBasic);
        if (clientSecretPost is not null) clientAuthentications.Add(clientSecretPost);
        if (clientAssertion is not null) clientAuthentications.Add(clientAssertion);
        if (clientId is not null) clientAuthentications.Add(clientId);

        return new TokenRequest
        {
            GrantType = grantType,
            DeviceCode = deviceCode,
            Code = code,
            CodeVerifier = codeVerifier,
            RedirectUri = redirectUri,
            RefreshToken = refreshToken,
            DPoP = dPoP,
            Scope = scope,
            Resource = resource,
            ClientAuthentications = clientAuthentications
        };
    }
}