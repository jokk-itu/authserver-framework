using AuthServer.Authentication.Abstractions;
using AuthServer.Authentication.Models;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Cache.Entities;
using AuthServer.Core.Request;

namespace AuthServer.TokenByGrant;
internal abstract class BaseTokenValidator
{
    private readonly IDPoPService _dPoPService;
    private readonly IClientAuthenticationService _clientAuthenticationService;
    private readonly ITokenAuthorizationValidatorService _scopeResourceService;

    protected BaseTokenValidator(
        IDPoPService dPoPService,
        IClientAuthenticationService clientAuthenticationService,
        ITokenAuthorizationValidatorService scopeResourceService)
    {
        _dPoPService = dPoPService;
        _clientAuthenticationService = clientAuthenticationService;
        _scopeResourceService = scopeResourceService;
    }

    protected async Task<ProcessResult<string, ProcessError>> AuthenticateClient(IReadOnlyCollection<ClientAuthentication> clientAuthentications, CancellationToken cancellationToken)
    {
        if (clientAuthentications.Count != 1)
        {
            return TokenError.MultipleOrNoneClientMethod;
        }

        var clientAuthentication = clientAuthentications.Single();
        var clientAuthenticationResult = await _clientAuthenticationService.AuthenticateClient(clientAuthentication, cancellationToken);
        if (!clientAuthenticationResult.IsAuthenticated || string.IsNullOrWhiteSpace(clientAuthenticationResult.ClientId))
        {
            return TokenError.InvalidClient;
        }

        return clientAuthenticationResult.ClientId;
    }

    protected async Task<ProcessResult<IReadOnlyCollection<string>, ProcessError>> ValidateTokenAuthorizationGrant(TokenAuthorizationGrantValidationDto validationDto, CancellationToken cancellationToken)
    {
        var scopeResourceValidationResult = await _scopeResourceService.ValidateTokenAuthorizationGrant(validationDto, cancellationToken);
        if (scopeResourceValidationResult.IsValid)
        {
            return new ProcessResult<IReadOnlyCollection<string>, ProcessError>(scopeResourceValidationResult.Scopes);
        }

        return scopeResourceValidationResult.Error switch
        {
            TokenAuthorizationValidationError.ConsentNotFound => TokenError.ConsentRequired,
            TokenAuthorizationValidationError.ScopeExceedsConsent => TokenError.ScopeExceedsConsentedScope,
            TokenAuthorizationValidationError.ResourceExceedsConsent => TokenError.ResourceExceedsConsentedResource,
            TokenAuthorizationValidationError.UnauthorizedClientForScope => TokenError.UnauthorizedForScope,
            TokenAuthorizationValidationError.UnauthorizedResourceForScope => TokenError.InvalidResource,
            _ => throw new NotSupportedException($"error {scopeResourceValidationResult.Error} is not supported")
        };
    }

    protected async Task<ProcessResult<IReadOnlyCollection<string>, ProcessError>> ValidateTokenAuthorizationClient(TokenAuthorizationClientValidationDto validationDto, CancellationToken cancellationToken)
    {
        var scopeResourceValidationResult = await _scopeResourceService.ValidateTokenAuthorizationClient(validationDto, cancellationToken);
        if (scopeResourceValidationResult.IsValid)
        {
            return new ProcessResult<IReadOnlyCollection<string>, ProcessError>(scopeResourceValidationResult.Scopes);
        }

        return scopeResourceValidationResult.Error switch
        {
            TokenAuthorizationValidationError.UnauthorizedClientForScope => TokenError.UnauthorizedForScope,
            TokenAuthorizationValidationError.UnauthorizedResourceForScope => TokenError.InvalidResource,
            _ => throw new NotSupportedException($"error {scopeResourceValidationResult.Error} is not supported")
        };
    }

    protected async Task<DPoPResult?> ValidateDPoP(string? dPoP, CachedClient cachedClient, string? jkt, CancellationToken cancellationToken)
    {
        var isDPoPRequired = cachedClient.RequireDPoPBoundAccessTokens || jkt is not null;
        if (isDPoPRequired && string.IsNullOrEmpty(dPoP))
        {
            return new DPoPResult
            {
                Error = TokenError.DPoPRequired
            };
        }

        if (string.IsNullOrEmpty(dPoP))
        {
            return null;
        }

        var dPoPValidationResult = await _dPoPService.ValidateDPoP(dPoP, cachedClient.Id, cancellationToken);
        if (dPoPValidationResult is { IsValid: false, RenewDPoPNonce: false })
        {
            return new DPoPResult
            {
                Error = TokenError.InvalidDPoP
            };
        }

        if (dPoPValidationResult is { IsValid: false, RenewDPoPNonce: true })
        {
            return new DPoPResult
            {
                Error = TokenError.RenewDPoPNonce(cachedClient.Id)
            };
        }

        if (jkt is not null && dPoPValidationResult.DPoPJkt != jkt)
        {
            return new DPoPResult
            {
                Error = TokenError.InvalidDPoPJktMatch
            };
        }

        return new DPoPResult
        {
            DPoPJkt = dPoPValidationResult.DPoPJkt
        };
    }

    protected class DPoPResult
    {
        public string? DPoPJkt { get; init; }
        public ProcessError? Error { get; init; }
    }
}