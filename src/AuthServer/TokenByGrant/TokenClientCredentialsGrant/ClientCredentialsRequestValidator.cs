using AuthServer.Authentication.Abstractions;
using AuthServer.Authorization.Abstractions;
using AuthServer.Cache.Abstractions;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;

namespace AuthServer.TokenByGrant.TokenClientCredentialsGrant;

internal class ClientCredentialsRequestValidator : BaseTokenValidator, IRequestValidator<TokenRequest, ClientCredentialsValidatedRequest>
{
    private readonly ICachedClientStore _cachedClientStore;

    public ClientCredentialsRequestValidator(
        IClientAuthenticationService clientAuthenticationService,
        ICachedClientStore cachedClientStore,
        IDPoPService dPoPService,
        IScopeResourceService scopeResourceService)
        : base(dPoPService, clientAuthenticationService, scopeResourceService)
    {
        _cachedClientStore = cachedClientStore;
    }

    public async Task<ProcessResult<ClientCredentialsValidatedRequest, ProcessError>> Validate(TokenRequest request, CancellationToken cancellationToken)
    {
        if (request.GrantType != GrantTypeConstants.ClientCredentials)
        {
            return TokenError.UnsupportedGrantType;
        }

        if (request.Scope.Count == 0)
        {
            return TokenError.InvalidScope;
        }

        if (request.Resource.Count == 0)
        {
            return TokenError.InvalidResource;
        }

        var clientAuthenticationResult = await AuthenticateClient(request.ClientAuthentications, cancellationToken);
        if (!clientAuthenticationResult.IsSuccess)
        {
            return clientAuthenticationResult.Error!;
        }

        var clientId = clientAuthenticationResult.Value!;
        var cachedClient = await _cachedClientStore.Get(clientId, cancellationToken);

        if (cachedClient.GrantTypes.All(x => x != GrantTypeConstants.ClientCredentials))
        {
            return TokenError.UnauthorizedForGrantType;
        }

        var dPoPResult = await ValidateDPoP(request.DPoP, cachedClient, null, cancellationToken);
        if (dPoPResult?.Error is not null)
        {
            return dPoPResult.Error;
        }

        var scopeValidationResult = await ValidateClientScopeResource(request.Scope, request.Resource, clientId, cancellationToken);
        if (!scopeValidationResult.IsSuccess)
        {
            return scopeValidationResult.Error!;
        }

        return new ClientCredentialsValidatedRequest
        {
            ClientId = clientId,
            DPoPJkt = dPoPResult?.DPoPJkt,
            Scope = request.Scope,
            Resource = request.Resource
        };
    }
}