using AuthServer.Authentication.Abstractions;
using AuthServer.Cache.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Entities;
using AuthServer.Repositories.Abstractions;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.EndSession;
internal class EndSessionRequestValidator : IRequestValidator<EndSessionRequest, EndSessionValidatedRequest>
{
    private readonly AuthorizationDbContext _authorizationDbContext;
    private readonly IUserAccessor<EndSessionUser> _endSessionUserAccessor;
    private readonly IServerTokenDecoder _serverTokenDecoder;
    private readonly ICachedClientStore _cachedClientStore;
    private readonly ISessionRepository _sessionRepository;

    public EndSessionRequestValidator(
        AuthorizationDbContext authorizationDbContext,
        IUserAccessor<EndSessionUser> endSessionUserAccessor,
        IServerTokenDecoder serverTokenDecoder,
        ICachedClientStore cachedClientStore,
        ISessionRepository sessionRepository)
    {
        _authorizationDbContext = authorizationDbContext;
        _endSessionUserAccessor = endSessionUserAccessor;
        _serverTokenDecoder = serverTokenDecoder;
        _cachedClientStore = cachedClientStore;
        _sessionRepository = sessionRepository;
    }

    public async Task<ProcessResult<EndSessionValidatedRequest, ProcessError>> Validate(EndSessionRequest request, CancellationToken cancellationToken)
    {
        var endSessionUser = _endSessionUserAccessor.TryGetUser();
        if (endSessionUser is null)
        {
            return EndSessionError.InteractionRequired;
        }

        string? subject;
        string? sessionId;
        string? clientId;

        if (!string.IsNullOrEmpty(request.IdTokenHint))
        {
            var token = await _serverTokenDecoder.Validate(request.IdTokenHint!, new ServerTokenDecodeArguments
            {
                ValidateLifetime = false,
                TokenTypes = [TokenTypeHeaderConstants.IdToken],
                Audiences = string.IsNullOrEmpty(request.ClientId) ? [] : [request.ClientId]
            }, cancellationToken);

            if (token is null)
            {
                return EndSessionError.InvalidIdToken;
            }

            if (token.Sub != endSessionUser.SubjectIdentifier)
            {
                return EndSessionError.IdTokenDoesNotMatchSubject;
            }

            subject = token.Sub;
            sessionId = token.Sid;
            clientId = token.ClientId;
        }
        else
        {
            subject = endSessionUser.SubjectIdentifier;
            sessionId = string.IsNullOrEmpty(subject)
                ? null
                : await _sessionRepository.GetActiveSessionId(subject, cancellationToken);

            clientId = request.ClientId;
        }

        var requiredParametersError = ValidateRequiredParameters(request, clientId);
        if (requiredParametersError is not null)
        {
            return requiredParametersError;
        }

        if (clientId is not null)
        {
            var unauthorizedClientError = await ValidateClientAuthorizedForPostLogoutRedirectUri(clientId, request, cancellationToken);
            if (unauthorizedClientError is not null)
            {
                return unauthorizedClientError;
            }
        }

        return new EndSessionValidatedRequest
        {
            SubjectIdentifier = subject,
            SessionId = sessionId,
            ClientId = clientId,
            LogoutAtIdentityProvider = endSessionUser.LogoutAtIdentityProvider
        };
    }

    private static ProcessError? ValidateRequiredParameters(EndSessionRequest request, string? clientId)
    {
        if (string.IsNullOrEmpty(request.PostLogoutRedirectUri)
            && !string.IsNullOrEmpty(request.State))
        {
            return EndSessionError.StateWithoutPostLogoutRedirectUri;
        }

        if (string.IsNullOrEmpty(request.State)
            && !string.IsNullOrEmpty(request.PostLogoutRedirectUri))
        {
            return EndSessionError.PostLogoutRedirectUriWithoutState;
        }

        if (string.IsNullOrEmpty(clientId)
            && string.IsNullOrEmpty(request.IdTokenHint)
            && !string.IsNullOrEmpty(request.PostLogoutRedirectUri))
        {
            return EndSessionError.PostLogoutRedirectUriWithoutClientIdOrIdTokenHint;
        }

        return null;
    }

    private async Task<ProcessError?> ValidateClientAuthorizedForPostLogoutRedirectUri(string clientId, EndSessionRequest request, CancellationToken cancellationToken)
    {
        var cachedClient = await _cachedClientStore.TryGet(clientId, cancellationToken);
        if (!string.IsNullOrEmpty(request.PostLogoutRedirectUri)
            && cachedClient?.PostLogoutRedirectUris.Contains(request.PostLogoutRedirectUri) != true)
        {
            return EndSessionError.UnauthorizedClientForPostLogoutRedirectUri;
        }

        return null;
    }
}