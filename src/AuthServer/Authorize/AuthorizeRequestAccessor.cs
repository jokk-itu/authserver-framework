﻿using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Extensions;
using Microsoft.AspNetCore.Http;

namespace AuthServer.Authorize;
internal class AuthorizeRequestAccessor : IRequestAccessor<AuthorizeRequest>
{
    public async Task<AuthorizeRequest> GetRequest(HttpRequest httpRequest)
    {
        return httpRequest.Method switch
        {
            "GET" => GetRequestFromQuery(httpRequest),
            "POST" => await GetRequestFromBody(httpRequest),
            _ => throw new NotSupportedException("Endpoint only supports GET and POST")
        };
    }

    private static AuthorizeRequest GetRequestFromQuery(HttpRequest httpRequest)
    {
        var query = httpRequest.Query;

        var loginHint = query.GetValue(Parameter.LoginHint);
        var display = query.GetValue(Parameter.Display);
        var responseMode = query.GetValue(Parameter.ResponseMode);
        var maxAge = query.GetValue(Parameter.MaxAge);
        var clientId = query.GetValue(Parameter.ClientId);
        var codeChallenge = query.GetValue(Parameter.CodeChallenge);
        var codeChallengeMethod = query.GetValue(Parameter.CodeChallengeMethod);
        var redirectUri = query.GetValue(Parameter.RedirectUri);
        var idTokenHint = query.GetValue(Parameter.IdTokenHint);
        var prompt = query.GetValue(Parameter.Prompt);
        var responseType = query.GetValue(Parameter.ResponseType);
        var nonce = query.GetValue(Parameter.Nonce);
        var state = query.GetValue(Parameter.State);
        var requestObject = query.GetValue(Parameter.Request);
        var requestUri = query.GetValue(Parameter.RequestUri);
        var grantId = query.GetValue(Parameter.GrantId);
        var grantManagementAction = query.GetValue(Parameter.GrantId);
        var dPoPJkt = query.GetValue(Parameter.DPoPJkt);

        var scope = query.GetSpaceDelimitedValue(Parameter.Scope);
        var acrValues = query.GetSpaceDelimitedValue(Parameter.AcrValues);

        var resource = query.GetCollectionValue(Parameter.Resource);

        return new AuthorizeRequest
        {
            IdTokenHint = idTokenHint,
            LoginHint = loginHint,
            Prompt = prompt,
            Display = display,
            ClientId = clientId,
            RedirectUri = redirectUri,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            ResponseType = responseType,
            Nonce = nonce,
            MaxAge = maxAge,
            State = state,
            ResponseMode = responseMode,
            RequestObject = requestObject,
            RequestUri = requestUri,
            GrantId = grantId,
            GrantManagementAction = grantManagementAction,
            DPoPJkt = dPoPJkt,
            Scope = scope,
            AcrValues = acrValues,
            Resource = resource
        };
    }

    private static async Task<AuthorizeRequest> GetRequestFromBody(HttpRequest httpRequest)
    {
        var body = await httpRequest.ReadFormAsync();

        var loginHint = body.GetValue(Parameter.LoginHint);
        var display = body.GetValue(Parameter.Display);
        var responseMode = body.GetValue(Parameter.ResponseMode);
        var maxAge = body.GetValue(Parameter.MaxAge);
        var clientId = body.GetValue(Parameter.ClientId);
        var codeChallenge = body.GetValue(Parameter.CodeChallenge);
        var codeChallengeMethod = body.GetValue(Parameter.CodeChallengeMethod);
        var redirectUri = body.GetValue(Parameter.RedirectUri);
        var idTokenHint = body.GetValue(Parameter.IdTokenHint);
        var prompt = body.GetValue(Parameter.Prompt);
        var responseType = body.GetValue(Parameter.ResponseType);
        var nonce = body.GetValue(Parameter.Nonce);
        var state = body.GetValue(Parameter.State);
        var requestObject = body.GetValue(Parameter.Request);
        var requestUri = body.GetValue(Parameter.RequestUri);
        var grantId = body.GetValue(Parameter.GrantId);
        var grantManagementAction = body.GetValue(Parameter.GrantId);
        var dPoPJkt = body.GetValue(Parameter.DPoPJkt);

        var scope = body.GetSpaceDelimitedValue(Parameter.Scope);
        var acrValues = body.GetSpaceDelimitedValue(Parameter.AcrValues);

        var resource = body.GetCollectionValue(Parameter.Resource);

        return new AuthorizeRequest
        {
            IdTokenHint = idTokenHint,
            LoginHint = loginHint,
            Prompt = prompt,
            Display = display,
            ClientId = clientId,
            RedirectUri = redirectUri,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            ResponseType = responseType,
            Nonce = nonce,
            MaxAge = maxAge,
            State = state,
            ResponseMode = responseMode,
            RequestObject = requestObject,
            RequestUri = requestUri,
            GrantId = grantId,
            GrantManagementAction = grantManagementAction,
            DPoPJkt = dPoPJkt,
            Scope = scope,
            AcrValues = acrValues,
            Resource = resource
        };
    }
}