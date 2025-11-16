using AuthServer.Authentication.Abstractions;
using AuthServer.Authorize.Abstractions;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Extensions;
using AuthServer.Options;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace AuthServer.Authorize;
internal class AuthorizeEndpointHandler : IEndpointHandler
{
    private readonly IRequestAccessor<AuthorizeRequest> _requestAccessor;
    private readonly IRequestHandler<AuthorizeRequest, AuthorizeResponse> _requestHandler;
    private readonly IAuthorizeResponseBuilder _authorizeResponseBuilder;
    private readonly IOptionsSnapshot<UserInteraction> _userInteractionOptions;
    private readonly IUserAccessor<AuthorizeUser> _authorizeUserAccessor;

    public AuthorizeEndpointHandler(
        IRequestAccessor<AuthorizeRequest> requestAccessor,
        IRequestHandler<AuthorizeRequest, AuthorizeResponse> requestHandler,
        IAuthorizeResponseBuilder authorizeResponseBuilder,
        IOptionsSnapshot<UserInteraction> userInteractionOptions,
        IUserAccessor<AuthorizeUser> authorizeUserAccessor)
    {
        _requestAccessor = requestAccessor;
        _requestHandler = requestHandler;
        _authorizeResponseBuilder = authorizeResponseBuilder;
        _userInteractionOptions = userInteractionOptions;
        _authorizeUserAccessor = authorizeUserAccessor;
    }

    public async Task<IResult> Handle(HttpContext httpContext, CancellationToken cancellationToken)
    {
        var request = await _requestAccessor.GetRequest(httpContext.Request);
        var response = await _requestHandler.Handle(request, cancellationToken);

        return await response.Match(
            async result =>
            {
                // remove the authorized user to reset the interaction flow
                _authorizeUserAccessor.ClearUser();

                var additionalParameters = new Dictionary<string, string>();
                if (result.AuthorizationCode is not null)
                {
                    additionalParameters.Add(Parameter.Code, result.AuthorizationCode);
                }

                return await _authorizeResponseBuilder.BuildResponse(
                    request,
                    additionalParameters,
                    httpContext.Response,
                    cancellationToken);
            },
            async error =>
            {
                if (error is AuthorizeInteractionError authorizeInteractionError)
                {
                    var substituteRequest = new Dictionary<string, string>
                    {
                        { Parameter.ClientId, authorizeInteractionError.ClientId },
                        { Parameter.RequestUri, authorizeInteractionError.RequestUri }
                    };

                    return error switch
                    {
                        { Error: ErrorCode.LoginRequired } => Results.Extensions.LocalRedirectWithForwardSubstitutedRequest(_userInteractionOptions.Value.LoginUri!, httpContext, substituteRequest),
                        { Error: ErrorCode.ConsentRequired } => Results.Extensions.LocalRedirectWithForwardSubstitutedRequest(_userInteractionOptions.Value.ConsentUri!, httpContext, substituteRequest),
                        _ => Results.Extensions.LocalRedirectWithForwardSubstitutedRequest(_userInteractionOptions.Value.AccountSelectionUri!, httpContext, substituteRequest)
                    };
                }

                // remove the authorized user to reset the interaction flow
                _authorizeUserAccessor.ClearUser();
                return error switch
                {
                    { ResultCode: ResultCode.Redirect } =>
                        await _authorizeResponseBuilder.BuildResponse(request, error.ToDictionary(), httpContext.Response, cancellationToken),
                    _ => Results.Extensions.OAuthBadRequest(error)
                };
            });
    }
}