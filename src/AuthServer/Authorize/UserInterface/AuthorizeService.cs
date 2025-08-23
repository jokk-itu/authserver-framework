using AuthServer.Authentication.Abstractions;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Authorize.Abstractions;
using AuthServer.Authorize.UserInterface.Abstractions;
using AuthServer.Cache.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Endpoints.Responses;
using AuthServer.Entities;
using AuthServer.Repositories.Abstractions;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthServer.Authorize.UserInterface;
internal class AuthorizeService : IAuthorizeService
{
    private readonly IConsentRepository _consentRepository;
    private readonly IAuthorizationGrantRepository _authorizationGrantRepository;
    private readonly ICachedClientStore _cachedClientStore;
    private readonly IUserClaimService _userClaimService;
    private readonly IAuthenticationContextReferenceResolver _authenticationContextResolver;
    private readonly ISecureRequestService _secureRequestService;
    private readonly IAuthorizeResponseBuilder _authorizeResponseBuilder;
    private readonly IAuthenticatedUserAccessor _authenticatedUserAccessor;
    private readonly IUserAccessor<AuthorizeUser> _authorizeUserAccessor;
    private readonly IServerTokenDecoder _serverTokenDecoder;

    public AuthorizeService(
        IConsentRepository consentRepository,
        IAuthorizationGrantRepository authorizationGrantRepository,
        ICachedClientStore cachedClientStore,
        IUserClaimService userClaimService,
        IAuthenticationContextReferenceResolver authenticationContextResolver,
        ISecureRequestService secureRequestService,
        IAuthorizeResponseBuilder authorizeResponseBuilder,
        IAuthenticatedUserAccessor authenticatedUserAccessor,
        IUserAccessor<AuthorizeUser> authorizeUserAccessor,
        IServerTokenDecoder serverTokenDecoder)
    {
        _consentRepository = consentRepository;
        _authorizationGrantRepository = authorizationGrantRepository;
        _cachedClientStore = cachedClientStore;
        _userClaimService = userClaimService;
        _authenticationContextResolver = authenticationContextResolver;
        _secureRequestService = secureRequestService;
        _authorizeResponseBuilder = authorizeResponseBuilder;
        _authenticatedUserAccessor = authenticatedUserAccessor;
        _authorizeUserAccessor = authorizeUserAccessor;
        _serverTokenDecoder = serverTokenDecoder;
    }

    /// <inheritdoc/>
    public async Task HandleAuthorizationGrant(string subjectIdentifier, AuthorizeRequestDto request, IReadOnlyCollection<string> amr, CancellationToken cancellationToken)
    {
        var isCreateAction = string.IsNullOrEmpty(request.GrantManagementAction)
                       || request.GrantManagementAction == GrantManagementActionConstants.Create;

        var acr = await _authenticationContextResolver.ResolveAuthenticationContextReference(amr, cancellationToken);

        if (isCreateAction)
        {
            var grant = await _authorizationGrantRepository.CreateAuthorizationCodeGrant(
                subjectIdentifier,
                request.ClientId!,
                acr,
                amr,
                cancellationToken);

            var authorizeUser = new AuthorizeUser(
                subjectIdentifier,
                true,
                grant.Id);

            _authorizeUserAccessor.SetUser(authorizeUser);
        }
        else
        {
            var grantId = request.GrantId!;

            await _authorizationGrantRepository.UpdateAuthorizationGrant(
                grantId,
                acr,
                amr,
                cancellationToken);

            _authorizeUserAccessor.SetUser(new AuthorizeUser(subjectIdentifier, true, grantId));
        }
    }

    /// <inheritdoc/>
    public async Task HandleConsent(string subjectIdentifier, string clientId, IReadOnlyCollection<string> consentedScopes, IReadOnlyCollection<string> consentedClaims, CancellationToken cancellationToken)
    {
        await _consentRepository.CreateOrUpdateClientConsent(subjectIdentifier, clientId, consentedScopes, consentedClaims, cancellationToken);
    }

    /// <inheritdoc/>
    public async Task<ConsentGrantDto> GetConsentGrantDto(string subjectIdentifier, string clientId, CancellationToken cancellationToken)
    {
        var consents = await _consentRepository.GetClientConsents(subjectIdentifier, clientId, cancellationToken);
        var cachedClient = await _cachedClientStore.Get(clientId, cancellationToken);
        var username = await _userClaimService.GetUsername(subjectIdentifier, cancellationToken);

        return new ConsentGrantDto
        {
            ClientName = cachedClient.Name,
            ClientLogoUri = cachedClient.LogoUri,
            ClientUri = cachedClient.ClientUri,
            Username = username,
            ConsentedScope = consents.OfType<ScopeConsent>().Select(x => x.Scope.Name),
            ConsentedClaims = consents.OfType<ClaimConsent>().Select(x => x.Claim.Name)
        };
    }

    /// <inheritdoc/>
    public async Task<AuthorizeRequestDto?> GetValidatedRequest(string requestUri, string clientId, CancellationToken cancellationToken)
    {
        return await _secureRequestService.GetRequestByPushedRequest(requestUri, clientId, cancellationToken);
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
}
