using AuthServer.Authentication.Abstractions;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Authorize;
using AuthServer.Authorize.Abstractions;
using AuthServer.Core;
using AuthServer.Endpoints.Responses;
using AuthServer.TokenDecoders.Abstractions;
using AuthServer.UserInterface.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthServer.UserInterface;

internal class AuthorizeService : IAuthorizeService
{
    private readonly ISecureRequestService _secureRequestService;
    private readonly IAuthorizeResponseBuilder _authorizeResponseBuilder;
    private readonly IAuthenticatedUserAccessor _authenticatedUserAccessor;
    private readonly IUserAccessor<AuthorizeUser> _authorizeUserAccessor;
    private readonly IServerTokenDecoder _serverTokenDecoder;

    public AuthorizeService(
        ISecureRequestService secureRequestService,
        IAuthorizeResponseBuilder authorizeResponseBuilder,
        IAuthenticatedUserAccessor authenticatedUserAccessor,
        IUserAccessor<AuthorizeUser> authorizeUserAccessor,
        IServerTokenDecoder serverTokenDecoder)
    {
        _secureRequestService = secureRequestService;
        _authorizeResponseBuilder = authorizeResponseBuilder;
        _authenticatedUserAccessor = authenticatedUserAccessor;
        _authorizeUserAccessor = authorizeUserAccessor;
        _serverTokenDecoder = serverTokenDecoder;
    }

    /// <inheritdoc/>
    public async Task<SubjectDto> GetSubject(AuthorizeRequestDto authorizeRequestDto, CancellationToken cancellationToken)
    {
        var authorizeUser = _authorizeUserAccessor.TryGetUser();
        if (authorizeUser is not null)
        {
            return new SubjectDto
            {
                Subject = authorizeUser.SubjectIdentifier,
                GrantId = authorizeUser.AuthorizationGrantId
            };
        }

        if (authorizeRequestDto.IdTokenHint is not null)
        {
            // only read the token, as it has already been validated previously
            var idTokenResult = await _serverTokenDecoder.Read(authorizeRequestDto.IdTokenHint, cancellationToken);
            return new SubjectDto
            {
                Subject = idTokenResult.Sub,
                GrantId = idTokenResult.GrantId!
            };
        }

        var authenticatedUser = await _authenticatedUserAccessor.GetAuthenticatedUser();
        if (authenticatedUser is not null)
        {
            return new SubjectDto
            {
                Subject = authenticatedUser.SubjectIdentifier,
                GrantId = authenticatedUser.AuthorizationGrantId
            };
        }

        throw new InvalidOperationException("subject cannot be deduced");
    }

    /// <inheritdoc/>
    public async Task<IActionResult> GetErrorResult(string requestUri, string clientId, OAuthError oauthError, HttpContext httpContext, CancellationToken cancellationToken)
    {
        _authorizeUserAccessor.ClearUser();

        var requestDto = await _secureRequestService.GetRequestByPushedRequest(requestUri, clientId, cancellationToken);
        if (requestDto is null)
        {
            return new BadRequestObjectResult(oauthError);
        }

        var request = new AuthorizeRequest(requestDto);
        var errorParameters = new Dictionary<string, string>
        {
            { Parameter.Error, oauthError.Error },
            { Parameter.ErrorDescription, oauthError.ErrorDescription }
        };
        return await _authorizeResponseBuilder.BuildResponse(request, errorParameters, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<AuthorizeRequestDto?> GetValidatedRequest(string requestUri, string clientId, CancellationToken cancellationToken)
    {
        return await _secureRequestService.GetRequestByPushedRequest(requestUri, clientId, cancellationToken);
    }
}