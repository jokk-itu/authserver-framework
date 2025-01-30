using AuthServer.Authentication.Abstractions;
using AuthServer.Authorize.Abstractions;
using AuthServer.Cache.Abstractions;
using AuthServer.Constants;
using AuthServer.Entities;
using AuthServer.Extensions;
using AuthServer.Repositories.Abstractions;
using AuthServer.RequestAccessors.Authorize;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.Extensions.Logging;

namespace AuthServer.Authorize;

internal class AuthorizeInteractionService : IAuthorizeInteractionService
{
    private readonly ITokenDecoder<ServerIssuedTokenDecodeArguments> _serverIssuedTokenDecoder;
    private readonly IAuthorizeUserAccessor _userAccessor;
    private readonly IAuthenticatedUserAccessor _authenticatedUserAccessor;
    private readonly IAuthorizationGrantRepository _authorizationGrantRepository;
    private readonly IConsentRepository _consentGrantRepository;
    private readonly ICachedClientStore _cachedClientStore;
    private readonly ILogger<AuthorizeInteractionService> _logger;

    public AuthorizeInteractionService(
        ITokenDecoder<ServerIssuedTokenDecodeArguments> serverIssuedTokenDecoder,
        IAuthorizeUserAccessor userAccessor,
        IAuthenticatedUserAccessor authenticatedUserAccessor,
        IAuthorizationGrantRepository authorizationGrantRepository,
        IConsentRepository consentGrantRepository,
        ICachedClientStore cachedClientStore,
        ILogger<AuthorizeInteractionService> logger)
    {
        _serverIssuedTokenDecoder = serverIssuedTokenDecoder;
        _userAccessor = userAccessor;
        _authenticatedUserAccessor = authenticatedUserAccessor;
        _authorizationGrantRepository = authorizationGrantRepository;
        _consentGrantRepository = consentGrantRepository;
        _cachedClientStore = cachedClientStore;
        _logger = logger;
    }

    /// <inheritdoc/>
    public async Task<InteractionResult> GetInteractionResult(AuthorizeRequest authorizeRequest, CancellationToken cancellationToken)
    {
        // user was redirected for interaction
        var authorizeUser = _userAccessor.TryGetUser();
        if (authorizeUser is not null)
        {
            _logger.LogDebug("Deducing prompt from interaction with {@User}", authorizeUser);
            var grantId = authorizeRequest.GrantId ?? authorizeUser.AuthorizationGrantId;
            return await GetPrompt(authorizeUser with { AuthorizationGrantId = grantId}, authorizeRequest, cancellationToken);
        }

        /*
         client provided prompt overrides automatically deducing prompt.
         none is not checked, as that requires further validating session.

         ordering of the checks matters.
         */
        if (authorizeRequest.Prompt?.Contains(PromptConstants.SelectAccount) == true)
        {
            _logger.LogDebug("Using prompt {Prompt} from request", authorizeRequest.Prompt);
            return InteractionResult.SelectAccountRedirectResult;
        }

        if (authorizeRequest.Prompt?.Contains(PromptConstants.Login) == true)
        {
            _logger.LogDebug("Using prompt {Prompt} from request", authorizeRequest.Prompt);
            return InteractionResult.LoginRedirectResult;
        }

        if (authorizeRequest.Prompt?.Contains(PromptConstants.Consent) == true)
        {
            _logger.LogDebug("Using prompt {Prompt} from request", authorizeRequest.Prompt);
            return InteractionResult.ConsentRedirectResult;
        }

        // id_token_hint overrides cookies, and only deduces prompt none, if validation succeeds
        if (!string.IsNullOrEmpty(authorizeRequest.IdTokenHint))
        {
            var decodedIdToken = await _serverIssuedTokenDecoder.Read(authorizeRequest.IdTokenHint);
            var subject = decodedIdToken.Subject;
            var grantId = authorizeRequest.GrantId ?? decodedIdToken.GetClaim(ClaimNameConstants.GrantId).Value;

            _logger.LogDebug("Deducing Prompt from id_token with subject {Subject} and grant {AuthorizationGrantId}", subject, grantId);

            return await GetPrompt(new AuthorizeUser(subject, false, grantId), authorizeRequest, cancellationToken);
        }

        var authenticatedUsers = await _authenticatedUserAccessor.CountAuthenticatedUsers();
        switch (authenticatedUsers)
        {
            case 0:
                _logger.LogDebug("No authenticated users, deducing prompt {Prompt}", PromptConstants.Login);
                return InteractionResult.LoginResult(authorizeRequest.Prompt);
            case > 1:
                _logger.LogDebug("Multiple authenticated users, deducing prompt {Prompt}", PromptConstants.SelectAccount);
                return InteractionResult.SelectAccountResult(authorizeRequest.Prompt);
            default:
                var authenticatedUser = (await _authenticatedUserAccessor.GetAuthenticatedUser())!;
                var subject = authenticatedUser.SubjectIdentifier;
                var grantId = authorizeRequest.GrantId ?? authenticatedUser.AuthorizationGrantId;

                _logger.LogDebug("Deducing Prompt from one authenticated user {@User}", authenticatedUser);

                return await GetPrompt(new AuthorizeUser(subject, false, grantId), authorizeRequest, cancellationToken);
        }
    }

    private async Task<InteractionResult> GetPrompt(AuthorizeUser authorizeUser, AuthorizeRequest authorizeRequest, CancellationToken cancellationToken)
    {
        var authorizationGrant = await _authorizationGrantRepository.GetActiveAuthorizationGrant(authorizeUser.AuthorizationGrantId, cancellationToken);
        if (authorizationGrant is null)
        {
            _logger.LogDebug("Grant {GrantId} has expired, deducing prompt {Prompt}", authorizeUser.AuthorizationGrantId, PromptConstants.Login);
            return InteractionResult.LoginResult(authorizeRequest.Prompt);
        }

        var maxAgePrompt = GetPromptMaxAge(authorizationGrant, authorizeRequest);
        if (!authorizeUser.IsFreshGrant && maxAgePrompt is not null)
        {
            return maxAgePrompt;
        }

        var acrPrompt = await GetPromptAcr(authorizationGrant, authorizeRequest, cancellationToken);
        if (acrPrompt is not null)
        {
            return acrPrompt;
        }

        var grantIdPrompt = GetPromptGrantId(authorizationGrant, authorizeRequest, authorizeUser.SubjectIdentifier);
        if (grantIdPrompt is not null)
        {
            return grantIdPrompt;
        }

        if (!authorizationGrant.Client.RequireConsent)
        {
            _logger.LogDebug("Client {ClientId} does not require consent, deducing prompt {Prompt}", authorizeRequest.ClientId, PromptConstants.None);
            return InteractionResult.Success(authorizeUser.SubjectIdentifier, authorizeUser.AuthorizationGrantId);
        }

        var consentedScope = await _consentGrantRepository.GetClientConsentedScopes(authorizeUser.SubjectIdentifier, authorizeRequest.ClientId!, cancellationToken);
        if (authorizeRequest.Scope.IsSubset(consentedScope))
        {
            _logger.LogDebug("User has not granted consent to scope {@Scope}, deducing prompt {Prompt}", authorizeRequest.Scope.Except(consentedScope), PromptConstants.Consent);
            return InteractionResult.ConsentResult(authorizeRequest.Prompt);
        }

        _logger.LogDebug("Deducing prompt {Prompt}", PromptConstants.None);
        return InteractionResult.Success(authorizeUser.SubjectIdentifier, authorizeUser.AuthorizationGrantId);
    }

    private async Task<InteractionResult?> GetPromptAcr(AuthorizationGrant authorizationGrant, AuthorizeRequest authorizeRequest, CancellationToken cancellationToken)
    {
        var performedAuthenticationContextReference = authorizationGrant.AuthenticationContextReference.Name;
        var defaultAuthenticationContextReferences = (await _cachedClientStore.Get(authorizeRequest.ClientId!, cancellationToken))!.DefaultAcrValues;

        if (authorizeRequest.AcrValues.Count != 0 && !authorizeRequest.AcrValues.Contains(performedAuthenticationContextReference))
        {
            _logger.LogDebug("Acr {@RequestedAcr} is not met, performed Acr {PerformedAcr}", authorizeRequest.AcrValues, performedAuthenticationContextReference);
            return InteractionResult.UnmetAuthenticationRequirementResult;
        }

        if (defaultAuthenticationContextReferences.Count != 0 && !defaultAuthenticationContextReferences.Contains(performedAuthenticationContextReference))
        {
            _logger.LogDebug("Acr {@DefaultAcr} is not met, performed Acr {PerformedAcr}", defaultAuthenticationContextReferences, performedAuthenticationContextReference);
            return InteractionResult.UnmetAuthenticationRequirementResult;
        }

        return null;
    }

    private InteractionResult? GetPromptMaxAge(AuthorizationGrant authorizationGrant, AuthorizeRequest authorizeRequest)
    {
        var hasMaxAge = int.TryParse(authorizeRequest.MaxAge, out var parsedMaxAge);
        var maxAge = hasMaxAge ? parsedMaxAge : authorizationGrant.Client.DefaultMaxAge;

        if (maxAge is not null && authorizationGrant.AuthTime.AddSeconds(maxAge.Value) < DateTime.UtcNow)
        {
            _logger.LogDebug("MaxAge {MaxAge} has been reached for grant {GrantId}, deducing prompt {Prompt}", maxAge, authorizationGrant.Id, PromptConstants.Login);
            return InteractionResult.LoginResult(authorizeRequest.Prompt);
        }

        return null;
    }

    private InteractionResult? GetPromptGrantId(AuthorizationGrant authorizationGrant, AuthorizeRequest authorizeRequest, string subjectIdentifier)
    {
        var hasGrantId = !string.IsNullOrEmpty(authorizeRequest.GrantId);
        if (hasGrantId && authorizationGrant.Session.SubjectIdentifier.Id != subjectIdentifier)
        {
            _logger.LogDebug("Subject {SubjectIdentifier} is not authorized for grantId {GrantId}", subjectIdentifier, authorizeRequest.GrantId);
            return InteractionResult.InvalidGrantId;
        }

        return null;
    }
}