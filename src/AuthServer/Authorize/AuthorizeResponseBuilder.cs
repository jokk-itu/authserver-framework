using System.Text;
using System.Web;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorize.Abstractions;
using AuthServer.Cache.Abstractions;
using AuthServer.Constants;
using AuthServer.Extensions;
using AuthServer.Options;
using AuthServer.RequestAccessors.Authorize;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Parameter = AuthServer.Core.Parameter;

namespace AuthServer.Authorize;

internal class AuthorizeResponseBuilder : IAuthorizeResponseBuilder
{
    private readonly IOptionsSnapshot<DiscoveryDocument> _discoveryDocumentOptions;
    private readonly ICachedClientStore _cachedClientStore;
    private readonly ISecureRequestService _authorizeRequestParameterService;

    public AuthorizeResponseBuilder(
        IOptionsSnapshot<DiscoveryDocument> discoveryDocumentOptions,
        ICachedClientStore cachedClientStore,
        ISecureRequestService authorizeRequestParameterService)
    {
        _discoveryDocumentOptions = discoveryDocumentOptions;
        _cachedClientStore = cachedClientStore;
        _authorizeRequestParameterService = authorizeRequestParameterService;
    }

    /// <inheritdoc/>
    public async Task<IActionResult> BuildResponse(AuthorizeRequest request, IDictionary<string, string> additionalParameters, CancellationToken cancellationToken)
    {
        var responseResult = await GetResponseResult(request, additionalParameters, cancellationToken);
        return responseResult.ResponseMode switch
        {
            ResponseModeConstants.Query => RedirectSeeOther(BuildRedirectUriWithQuery(responseResult)),
            ResponseModeConstants.Fragment => RedirectSeeOther(BuildRedirectUriWithFragment(responseResult)),
            ResponseModeConstants.FormPost => OkHtml(BuildFormPost(responseResult)),
            _ => throw new ArgumentException("Unexpected response_mode value", nameof(request))
        };
    }

    /// <inheritdoc />
    public async Task<IResult> BuildResponse(AuthorizeRequest request, IDictionary<string, string> additionalParameters, HttpResponse httpResponse, CancellationToken cancellationToken)
    {
        var responseResult = await GetResponseResult(request, additionalParameters, cancellationToken);
        return responseResult.ResponseMode switch
        {
            ResponseModeConstants.Query => Results.Extensions.OAuthSeeOtherRedirect(BuildRedirectUriWithQuery(responseResult), httpResponse),
            ResponseModeConstants.Fragment => Results.Extensions.OAuthSeeOtherRedirect(BuildRedirectUriWithFragment(responseResult), httpResponse),
            ResponseModeConstants.FormPost => Results.Extensions.OAuthOkWithHtml(BuildFormPost(responseResult)),
            _ => throw new ArgumentException("Unexpected response_mode value", nameof(request))
        };
    }

    private async Task<ResponseResult> GetResponseResult(AuthorizeRequest authorizeRequest, IDictionary<string, string> additionalParameters, CancellationToken cancellationToken)
    {
        if (!string.IsNullOrEmpty(authorizeRequest.RequestUri)
            || !string.IsNullOrEmpty(authorizeRequest.RequestObject))
        {
            var newRequest = _authorizeRequestParameterService.GetCachedRequest();
            authorizeRequest = new AuthorizeRequest
            {
                IdTokenHint = newRequest.IdTokenHint,
                LoginHint = newRequest.LoginHint,
                Prompt = newRequest.Prompt,
                Display = newRequest.Display,
                ClientId = newRequest.ClientId,
                RedirectUri = newRequest.RedirectUri,
                CodeChallenge = newRequest.CodeChallenge,
                CodeChallengeMethod = newRequest.CodeChallengeMethod,
                ResponseType = newRequest.ResponseType,
                Nonce = newRequest.Nonce,
                MaxAge = newRequest.MaxAge,
                State = newRequest.State,
                ResponseMode = newRequest.ResponseMode,
                GrantId = newRequest.GrantId,
                GrantManagementAction = newRequest.GrantManagementAction,
                Scope = newRequest.Scope,
                AcrValues = newRequest.AcrValues
            };
        }

        var responseMode = authorizeRequest.ResponseMode;
        if (string.IsNullOrEmpty(responseMode))
        {
            responseMode = DeduceResponseMode(authorizeRequest.ResponseType!);
        }

        additionalParameters.Add(Parameter.State, authorizeRequest.State!);

        if (responseMode is ResponseModeConstants.FormPost)
        {
            additionalParameters.Add(Parameter.Issuer, _discoveryDocumentOptions.Value.Issuer);
        }

        var redirectUri = authorizeRequest.RedirectUri;
        if (string.IsNullOrEmpty(redirectUri))
        {
            var cachedClient = await _cachedClientStore.Get(authorizeRequest.ClientId!, cancellationToken);
            redirectUri = cachedClient.RedirectUris.Single();
        }

        return new ResponseResult(responseMode, redirectUri, additionalParameters);
    } 

    private static string BuildRedirectUriWithQuery(ResponseResult responseResult)
    {
        var builder = new StringBuilder();
        builder.Append('?');
        AddParameters(builder, responseResult.Parameters);
        var query = builder.ToString();
        return responseResult.RedirectUri + query;
    }

    private static string BuildRedirectUriWithFragment(ResponseResult responseResult)
    {
        var builder = new StringBuilder();
        builder.Append('#');
        AddParameters(builder, responseResult.Parameters);
        var fragment = builder.ToString();
        return responseResult.RedirectUri + fragment;
    }

    private static void AddParameters(StringBuilder builder, IDictionary<string, string> parameters)
    {
        builder.AppendJoin('&', parameters.Select(x => x.Key + '=' + HttpUtility.UrlEncode(x.Value)));
    }

    private static string BuildFormPost(ResponseResult responseResult)
    {
        var formPrefix = $"""<html><head><title>Submit Form</title></head><body onload="javascript:document.forms[0].submit()"><form method="post" action="{responseResult.RedirectUri}">""";
        const string formSuffix = "</form></body></html>";
        var formBuilder = new StringBuilder();

        formBuilder.Append(formPrefix);
        foreach (var parameter in responseResult.Parameters)
        {
            formBuilder.Append($"""<input type="hidden" name="{parameter.Key}" value="{parameter.Value}" />""");
        }
        formBuilder.Append(formSuffix);

        return formBuilder.ToString();
    }

    private static string DeduceResponseMode(string responseType)
    {
        return responseType switch
        {
            ResponseTypeConstants.Code => ResponseModeConstants.Query,
            _ => throw new ArgumentException("Unexpected value", nameof(responseType))
        };
    }

    private static RedirectResult RedirectSeeOther(string redirectUri) => new(redirectUri, false, true);
    private static ContentResult OkHtml(string html) => new()
    {
        Content = html,
        ContentType = MimeTypeConstants.Html,
        StatusCode = StatusCodes.Status200OK
    };

    private sealed record ResponseResult(string ResponseMode, string RedirectUri, IDictionary<string, string> Parameters);
}