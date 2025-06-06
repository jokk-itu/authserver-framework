﻿using AuthServer.Authentication.Models;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Extensions;
using AuthServer.TokenDecoders;
using Microsoft.AspNetCore.Http;

namespace AuthServer.PushedAuthorization;
internal class PushedAuthorizationRequestAccessor : IRequestAccessor<PushedAuthorizationRequest >
{
    public async Task<PushedAuthorizationRequest> GetRequest(HttpRequest httpRequest)
    {
        var dPoP = httpRequest.Headers.GetValue(Parameter.DPoP);

        var body = await httpRequest.ReadFormAsync();

        var loginHint = body.GetValue(Parameter.LoginHint);
        var display = body.GetValue(Parameter.Display);
        var responseMode = body.GetValue(Parameter.ResponseMode);
        var maxAge = body.GetValue(Parameter.MaxAge);
        var codeChallenge = body.GetValue(Parameter.CodeChallenge);
        var codeChallengeMethod = body.GetValue(Parameter.CodeChallengeMethod);
        var redirectUri = body.GetValue(Parameter.RedirectUri);
        var idTokenHint = body.GetValue(Parameter.IdTokenHint);
        var prompt = body.GetValue(Parameter.Prompt);
        var responseType = body.GetValue(Parameter.ResponseType);
        var nonce = body.GetValue(Parameter.Nonce);
        var state = body.GetValue(Parameter.State);
        var grantId = body.GetValue(Parameter.GrantId);
        var grantManagementAction = body.GetValue(Parameter.GrantManagementAction);
        var dPoPJkt = body.GetValue(Parameter.DPoPJkt);
        var requestObject = body.GetValue(Parameter.Request);

        var scope = body.GetSpaceDelimitedValue(Parameter.Scope);
        var acrValues = body.GetSpaceDelimitedValue(Parameter.AcrValues);
        var resource = body.GetSpaceDelimitedValue(Parameter.Resource);

        var clientSecretBasic = httpRequest.GetClientSecretBasic();
        var clientSecretPost = body.GetClientSecretPost();
        var clientAssertion = body.GetClientAssertion(ClientTokenAudience.PushedAuthorizationEndpoint);

        var clientAuthentications = new List<ClientAuthentication>();
        if (clientSecretBasic is not null) clientAuthentications.Add(clientSecretBasic);
        if (clientSecretPost is not null) clientAuthentications.Add(clientSecretPost);
        if (clientAssertion is not null) clientAuthentications.Add(clientAssertion);

        return new PushedAuthorizationRequest
        {
            IdTokenHint = idTokenHint,
            LoginHint = loginHint,
            Prompt = prompt,
            Display = display,
            RedirectUri = redirectUri,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            ResponseType = responseType,
            Nonce = nonce,
            MaxAge = maxAge,
            State = state,
            ResponseMode = responseMode,
            GrantId = grantId,
            GrantManagementAction = grantManagementAction,
            DPoPJkt = dPoPJkt,
            DPoP = dPoP,
            RequestObject = requestObject,
            Scope = scope,
            AcrValues = acrValues,
            Resource = resource,
            ClientAuthentications = clientAuthentications.AsReadOnly()
        };
    }
}
