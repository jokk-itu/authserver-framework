using AuthServer.Authentication.Models;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Extensions;
using AuthServer.TokenDecoders;
using Microsoft.AspNetCore.Http;

namespace AuthServer.DeviceAuthorization;

internal class DeviceAuthorizationRequestAccessor : IRequestAccessor<DeviceAuthorizationRequest>
{
    public async Task<DeviceAuthorizationRequest> GetRequest(HttpRequest httpRequest)
    {
        var dPoP = httpRequest.Headers.GetValue(Parameter.DPoP);

        var body = await httpRequest.ReadFormAsync();

        var codeChallenge = body.GetValue(Parameter.CodeChallenge);
        var codeChallengeMethod = body.GetValue(Parameter.CodeChallengeMethod);
        var nonce = body.GetValue(Parameter.Nonce);
        var grantId = body.GetValue(Parameter.GrantId);
        var grantManagementAction = body.GetValue(Parameter.GrantManagementAction);
        var requestObject = body.GetValue(Parameter.Request);

        var scope = body.GetSpaceDelimitedValue(Parameter.Scope);
        var acrValues = body.GetSpaceDelimitedValue(Parameter.AcrValues);
        var resource = body.GetSpaceDelimitedValue(Parameter.Resource);

        var clientSecretBasic = httpRequest.GetClientSecretBasic();
        var clientSecretPost = body.GetClientSecretPost();
        var clientAssertion = body.GetClientAssertion(ClientTokenAudience.DeviceAuthorizationEndpoint);

        var clientAuthentications = new List<ClientAuthentication>();
        if (clientSecretBasic is not null) clientAuthentications.Add(clientSecretBasic);
        if (clientSecretPost is not null) clientAuthentications.Add(clientSecretPost);
        if (clientAssertion is not null) clientAuthentications.Add(clientAssertion);

        return new DeviceAuthorizationRequest
        {
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            Nonce = nonce,
            GrantId = grantId,
            GrantManagementAction = grantManagementAction,
            DPoP = dPoP,
            RequestObject = requestObject,
            Scope = scope,
            AcrValues = acrValues,
            Resource = resource,
            ClientAuthentications = clientAuthentications.AsReadOnly()
        };
    }
}