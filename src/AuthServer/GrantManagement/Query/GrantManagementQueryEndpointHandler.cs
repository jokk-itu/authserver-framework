using AuthServer.Authentication.OAuthToken;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Endpoints.Responses;
using AuthServer.Extensions;
using AuthServer.RequestAccessors.GrantManagement;
using Microsoft.AspNetCore.Http;

namespace AuthServer.GrantManagement.Query;

internal class GrantManagementQueryEndpointHandler : IEndpointHandler
{
    private readonly IRequestAccessor<GrantManagementRequest> _requestAccessor;
    private readonly IRequestHandler<GrantManagementRequest, GrantResponse> _requestHandler;

    public GrantManagementQueryEndpointHandler(
        IRequestAccessor<GrantManagementRequest> requestAccessor,
        IRequestHandler<GrantManagementRequest, GrantResponse> requestHandler)
    {
        _requestAccessor = requestAccessor;
        _requestHandler = requestHandler;
    }

    public async Task<IResult> Handle(HttpContext httpContext, CancellationToken cancellationToken)
    {
        var request = await _requestAccessor.GetRequest(httpContext.Request);
        var result = await _requestHandler.Handle(request, cancellationToken);
        return result.Match(
            response => Results.Ok(new GetGrantResponse
            {
                Scopes = response.Scopes.Select(x => new GetGrantScopeDto
                {
                    Scopes = x.Scopes,
                    Resources = x.Resources
                }),
                Claims = response.Claims
            }),
            error =>
                error.ResultCode switch
                {
                    ResultCode.NotFound => Results.Extensions.OAuthNotFound(error),
                    ResultCode.Forbidden => Results.Forbid(null, [OAuthTokenAuthenticationDefaults.AuthenticationScheme]),
                    _ => Results.Extensions.OAuthBadRequest(
                        new OAuthError(ErrorCode.ServerError, "unexpected error occurred"))
                });
    }
}