using AuthServer.Authentication.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Authorize;
using AuthServer.Authorize.Abstractions;
using AuthServer.Constants;
using AuthServer.Repositories.Abstractions;
using AuthServer.UserInterface.Abstractions;

namespace AuthServer.UserInterface;

internal class AuthorizationCodeGrantService : IAuthorizationCodeGrantService
{
    private readonly IAuthenticationContextReferenceResolver _authenticationContextReferenceResolver;
    private readonly IAuthorizationGrantRepository _authorizationGrantRepository;
    private readonly IUserAccessor<AuthorizeUser> _authorizeUserAccessor;

    public AuthorizationCodeGrantService(
        IAuthenticationContextReferenceResolver authenticationContextReferenceResolver,
        IAuthorizationGrantRepository authorizationGrantRepository,
        IUserAccessor<AuthorizeUser> authorizeUserAccessor)
    {
        _authenticationContextReferenceResolver = authenticationContextReferenceResolver;
        _authorizationGrantRepository = authorizationGrantRepository;
        _authorizeUserAccessor = authorizeUserAccessor;
    }

    /// <inheritdoc/>
    public async Task<string> HandleAuthorizationCodeGrant(string subjectIdentifier, AuthorizeRequestDto request, IReadOnlyCollection<string> amr, CancellationToken cancellationToken)
    {
        var isCreateAction = string.IsNullOrEmpty(request.GrantManagementAction)
                             || request.GrantManagementAction == GrantManagementActionConstants.Create;

        var acr = await _authenticationContextReferenceResolver.ResolveAuthenticationContextReference(amr, cancellationToken);

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

            return grant.Id;
        }
        else
        {
            var grantId = request.GrantId!;

            await _authorizationGrantRepository.UpdateAuthorizationCodeGrant(
                grantId,
                acr,
                amr,
                cancellationToken);

            var authorizeUser = new AuthorizeUser(
                subjectIdentifier,
                false,
                grantId);

            _authorizeUserAccessor.SetUser(authorizeUser);

            return grantId;
        }
    }
}