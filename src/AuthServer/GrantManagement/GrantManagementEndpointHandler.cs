using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Endpoints.Responses;
using AuthServer.Extensions;
using AuthServer.RequestAccessors.GrantManagement;
using Microsoft.AspNetCore.Http;

namespace AuthServer.GrantManagement;

internal class GrantManagementEndpointHandler : IEndpointHandler
{
    private readonly IRequestAccessor<GrantManagementRequest> _requestAccessor;
    private readonly IRequestHandler<GrantManagementRequest, Unit> _requestHandler;

    public GrantManagementEndpointHandler(
        IRequestAccessor<GrantManagementRequest> requestAccessor,
        IRequestHandler<GrantManagementRequest, Unit> requestHandler)
    {
        _requestAccessor = requestAccessor;
        _requestHandler = requestHandler;
    }
    
    public async Task<IResult> Handle(HttpContext httpContext, CancellationToken cancellationToken)
    {
        var request = await _requestAccessor.GetRequest(httpContext.Request);
        var result = await _requestHandler.Handle(request, cancellationToken);
        return result.Match(
            _ => Results.NoContent(),
            error =>
                error.ResultCode switch
                {
                    ResultCode.BadRequest => Results.Extensions.OAuthBadRequest(error),
                    _ => Results.Extensions.OAuthBadRequest(
                        new OAuthError(ErrorCode.ServerError, "unexpected error occurred"))
                });
    }
}