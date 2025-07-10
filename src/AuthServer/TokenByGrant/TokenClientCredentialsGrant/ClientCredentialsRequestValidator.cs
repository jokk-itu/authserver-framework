using AuthServer.Authentication.Abstractions;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Cache.Abstractions;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Extensions;
using AuthServer.Repositories.Abstractions;

namespace AuthServer.TokenByGrant.TokenClientCredentialsGrant;

internal class ClientCredentialsRequestValidator : IRequestValidator<TokenRequest, ClientCredentialsValidatedRequest>
{
    private readonly IClientAuthenticationService _clientAuthenticationService;
    private readonly ICachedClientStore _cachedClientStore;
    private readonly IClientRepository _clientRepository;
    private readonly IDPoPService _dPoPService;

    public ClientCredentialsRequestValidator(
        IClientAuthenticationService clientAuthenticationService,
        ICachedClientStore cachedClientStore,
        IClientRepository clientRepository,
        IDPoPService dPoPService)
    {
        _clientAuthenticationService = clientAuthenticationService;
        _cachedClientStore = cachedClientStore;
        _clientRepository = clientRepository;
        _dPoPService = dPoPService;
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

        var isClientAuthenticationMethodInvalid = request.ClientAuthentications.Count != 1;
        if (isClientAuthenticationMethodInvalid)
        {
            return TokenError.MultipleOrNoneClientMethod;
        }

        var clientAuthentication = request.ClientAuthentications.Single();
        var clientAuthenticationResult = await _clientAuthenticationService.AuthenticateClient(clientAuthentication, cancellationToken);
        if (!clientAuthenticationResult.IsAuthenticated)
        {
            return TokenError.InvalidClient;
        }

        var clientId = clientAuthenticationResult.ClientId!;
        var cachedClient = await _cachedClientStore.Get(clientId, cancellationToken);

        var isClientAuthorizedForClientCredentials = cachedClient.GrantTypes.Contains(GrantTypeConstants.ClientCredentials);
        if (!isClientAuthorizedForClientCredentials)
        {
            return TokenError.UnauthorizedForGrantType;
        }

        if (cachedClient.RequireDPoPBoundAccessTokens && string.IsNullOrEmpty(request.DPoP))
        {
            return TokenError.DPoPRequired;
        }

        var dPoPValidationResult = new DPoPValidationResult
        {
            IsValid = false
        };
        if (!string.IsNullOrEmpty(request.DPoP))
        {
            dPoPValidationResult = await _dPoPService.ValidateDPoP(request.DPoP, clientId, cancellationToken);
            if (dPoPValidationResult is { IsValid: false, DPoPNonce: null, RenewDPoPNonce: false })
            {
                return TokenError.InvalidDPoP;
            }

            if (dPoPValidationResult is { IsValid: false, DPoPNonce: not null })
            {
                return TokenError.UseDPoPNonce(dPoPValidationResult.DPoPNonce!);
            }

            if (dPoPValidationResult is { IsValid: false, RenewDPoPNonce: true })
            {
                return TokenError.RenewDPoPNonce(clientId);
            }
        }

        if (request.Scope.IsNotSubset(cachedClient.Scopes))
        {
            return TokenError.UnauthorizedForScope;
        }

        var doesResourcesExist = await _clientRepository.DoesResourcesExist(request.Resource, request.Scope, cancellationToken);
        if (!doesResourcesExist)
        {
            return TokenError.InvalidResource;
        }

        return new ClientCredentialsValidatedRequest
        {
            ClientId = clientId,
            DPoPJkt = dPoPValidationResult.DPoPJkt,
            Scope = request.Scope,
            Resource = request.Resource
        };
    }
}