using AuthServer.Authentication.Abstractions;
using AuthServer.Authorization.Abstractions;
using AuthServer.Cache.Abstractions;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Helpers;
using AuthServer.Repositories.Abstractions;
using AuthServer.TokenByGrant.TokenExchangeGrant.Abstractions;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;

namespace AuthServer.TokenByGrant.TokenExchangeGrant;
internal class TokenExchangeRequestValidator : BaseTokenValidator, IRequestValidator<TokenRequest, TokenExchangeValidatedRequest>
{
    private readonly IServerTokenDecoder _serverTokenDecoder;
    private readonly ICachedClientStore _cachedClientStore;
    private readonly IEnumerable<IExtendedTokenExchangeRequestValidator> _extendedTokenExchangeRequestValidators;

    public TokenExchangeRequestValidator(
        IDPoPService dPoPService,
        IClientAuthenticationService clientAuthenticationService,
        IConsentRepository consentRepository,
        IClientRepository clientRepository,
        IServerTokenDecoder serverTokenDecoder,
        ICachedClientStore cachedClientStore,
        IEnumerable<IExtendedTokenExchangeRequestValidator> extendedTokenExchangeRequestValidators)
        : base(dPoPService, clientAuthenticationService, consentRepository, clientRepository)
    {
        _serverTokenDecoder = serverTokenDecoder;
        _cachedClientStore = cachedClientStore;
        _extendedTokenExchangeRequestValidators = extendedTokenExchangeRequestValidators;
    }

    public async Task<ProcessResult<TokenExchangeValidatedRequest, ProcessError>> Validate(TokenRequest request, CancellationToken cancellationToken)
    {
        var validateParametersError = ValidateParameters(request);
        if (validateParametersError is not null)
        {
            return validateParametersError;
        }

        var clientAuthenticationResult = await AuthenticateClient(request.ClientAuthentications, cancellationToken);
        if (!clientAuthenticationResult.IsSuccess)
        {
            return clientAuthenticationResult.Error!;
        }

        var clientId = clientAuthenticationResult.Value!;
        var cachedClient = await _cachedClientStore.Get(clientId, cancellationToken);

        if (cachedClient.GrantTypes.All(x => x != GrantTypeConstants.TokenExchange))
        {
            return TokenError.UnauthorizedForGrantType;
        }

        var subjectTokenResult = await _serverTokenDecoder.Validate(
            request.SubjectToken!,
            new ServerTokenDecodeArguments
            {
                ValidateLifetime = true,
                Audiences = [],
                TokenTypes = [TokenHelper.MapTokenTypeIdentifierToTokenTypHeader(request.SubjectTokenType!)]
            },
            cancellationToken);

        if (subjectTokenResult is null)
        {
            return TokenError.InvalidSubjectToken;
        }

        if (subjectTokenResult.Act is not null
            && string.IsNullOrEmpty(request.ActorToken))
        {
            return TokenError.InvalidActorToken;
        }

        if (request.RequestedTokenType == TokenTypeIdentifier.IdToken
            && subjectTokenResult.GrantId is null)
        {
            return TokenError.InvalidSubjectTokenForRequestedTokenType;
        }

        TokenResult? actorTokenResult = null;
        if (!string.IsNullOrEmpty(request.ActorToken))
        {
            actorTokenResult = await _serverTokenDecoder.Validate(
                request.ActorToken,
                new ServerTokenDecodeArguments
                {
                    ValidateLifetime = true,
                    Audiences = [],
                    TokenTypes = [ TokenHelper.MapTokenTypeIdentifierToTokenTypHeader(request.ActorTokenType!) ]
                },
                cancellationToken);

            if (actorTokenResult is null)
            {
                return TokenError.InvalidActorToken;
            }

            if (subjectTokenResult.MayAct is not null
                && subjectTokenResult.MayAct!.Sub != actorTokenResult.Sub)
            {
                return TokenError.ActorIsUnauthorizedForSubjectToken;
            }
        }

        if (request.RequestedTokenType != TokenTypeIdentifier.AccessToken
            && !string.IsNullOrEmpty(request.DPoP))
        {
            return TokenError.InvalidDPoPForRequestedTokenType;
        }

        var dPoPValidationResult = await ValidateDPoP(request.DPoP, cachedClient, null, cancellationToken);
        if (dPoPValidationResult?.Error is not null)
        {
            return dPoPValidationResult.Error;
        }

        if (request.RequestedTokenType == TokenTypeIdentifier.AccessToken)
        {
            var subjectTokenClient = await _cachedClientStore.Get(subjectTokenResult.ClientId, cancellationToken);
            var scopeValidationResult = await ValidateScope(request.Scope, request.Resource, subjectTokenResult.GrantId, subjectTokenClient, cancellationToken);
            if (!scopeValidationResult.IsSuccess)
            {
                return scopeValidationResult.Error!;
            }
        }

        var extensionProcessError = await ExtensionValidate(request, clientId, cancellationToken);
        if (extensionProcessError is not null)
        {
            return extensionProcessError;
        }

        return new TokenExchangeValidatedRequest
        {
            RequestedTokenType = request.RequestedTokenType!,
            SubjectToken = subjectTokenResult,
            ActorToken = actorTokenResult,
            Jkt = dPoPValidationResult?.DPoPJkt,
            Scope = request.Scope,
            Resource = request.Resource
        };
    }

    private static ProcessError? ValidateParameters(TokenRequest request)
    {
        if (request.GrantType != GrantTypeConstants.TokenExchange)
        {
            return TokenError.UnsupportedGrantType;
        }

        if (!TokenTypeIdentifier.TokenTypeIdentifiers.Contains(request.RequestedTokenType))
        {
            return TokenError.InvalidRequestedTokenType;
        }

        if (string.IsNullOrEmpty(request.ActorToken) != string.IsNullOrEmpty(request.ActorTokenType))
        {
            return TokenError.InvalidActorTokenAndActorTokenType;
        }

        if (!string.IsNullOrEmpty(request.ActorTokenType) &&
            !TokenTypeIdentifier.TokenTypeIdentifiers.Contains(request.ActorTokenType))
        {
            return TokenError.InvalidActorTokenType;
        }

        if (string.IsNullOrEmpty(request.SubjectToken))
        {
            return TokenError.InvalidSubjectToken;
        }

        if (string.IsNullOrEmpty(request.SubjectTokenType))
        {
            return TokenError.InvalidSubjectTokenType;
        }

        return null;
    }

    private async Task<ProcessError?> ExtensionValidate(TokenRequest request, string clientId, CancellationToken cancellationToken)
    {
        foreach (var extendedTokenExchangeRequestValidator in _extendedTokenExchangeRequestValidators)
        {
            var oAuthError = await extendedTokenExchangeRequestValidator.Validate(
                new ValidatedTokenExchangeRequest
                {
                    ClientId = clientId,
                    RequestedTokenType = request.RequestedTokenType!,
                    SubjectToken = request.SubjectToken!,
                    SubjectTokenType = request.SubjectTokenType!,
                    ActorToken = request.ActorToken,
                    ActorTokenType = request.ActorTokenType,
                    Resource = request.Resource,
                    Scope = request.Scope,
                },
                cancellationToken);

            if (oAuthError is not null)
            {
                return new ProcessError(oAuthError.Error, oAuthError.ErrorDescription, ResultCode.BadRequest);
            }
        }

        return null;
    }
}