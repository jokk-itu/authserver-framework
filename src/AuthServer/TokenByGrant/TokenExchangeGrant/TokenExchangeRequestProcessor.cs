using AuthServer.Cache.Abstractions;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.TokenBuilders;
using AuthServer.TokenBuilders.Abstractions;

namespace AuthServer.TokenByGrant.TokenExchangeGrant;

internal class TokenExchangeRequestProcessor : IRequestProcessor<TokenExchangeValidatedRequest, TokenResponse>
{
    private readonly ITokenBuilder<GrantAccessTokenArguments> _grantAccessTokenBuilder;
    private readonly ITokenBuilder<ClientAccessTokenArguments> _clientAccessTokenBuilder;
    private readonly ITokenBuilder<IdTokenArguments> _idTokenBuilder;
    private readonly ICachedClientStore _cachedClientStore;

    public TokenExchangeRequestProcessor(
        ITokenBuilder<GrantAccessTokenArguments> grantAccessTokenBuilder,
        ITokenBuilder<ClientAccessTokenArguments> clientAccessTokenBuilder,
        ITokenBuilder<IdTokenArguments> idTokenBuilder,
        ICachedClientStore cachedClientStore)
    {
        _grantAccessTokenBuilder = grantAccessTokenBuilder;
        _clientAccessTokenBuilder = clientAccessTokenBuilder;
        _idTokenBuilder = idTokenBuilder;
        _cachedClientStore = cachedClientStore;
    }

    public async Task<TokenResponse> Process(TokenExchangeValidatedRequest request, CancellationToken cancellationToken)
    {
        string token;
        if (request is { RequestedTokenType: TokenTypeIdentifier.AccessToken, SubjectToken.GrantId: null })
        {
            token = await _clientAccessTokenBuilder.BuildToken(
                new ClientAccessTokenArguments
                {
                    ClientId = request.SubjectToken.ClientId,
                    Scope = request.Scope,
                    Resource = request.Resource,
                    Jkt = request.Jkt,
                    SubjectActor = request.ActorToken?.Sub
                },
                cancellationToken);
        }
        else if (request is { RequestedTokenType: TokenTypeIdentifier.AccessToken, SubjectToken.GrantId: not null })
        {
            token = await _grantAccessTokenBuilder.BuildToken(
                new GrantAccessTokenArguments
                {
                    AuthorizationGrantId = request.SubjectToken.GrantId,
                    Scope = request.Scope,
                    Resource = request.Resource,
                    Jkt = request.Jkt,
                    SubjectActor = request.ActorToken?.Sub
                },
                cancellationToken);
        }
        else
        {
            token = await _idTokenBuilder.BuildToken(
                new IdTokenArguments
                {
                    AuthorizationGrantId = request.SubjectToken.GrantId!,
                    Scope = request.Scope,
                    SubjectActor = request.ActorToken?.Sub,
                    EncyptorClientId = request.ActorToken?.ClientId
                },
                cancellationToken);
        }

        var cachedClient = await _cachedClientStore.Get(request.SubjectToken.ClientId, cancellationToken);
        var expiresIn = request.RequestedTokenType == TokenTypeIdentifier.IdToken
            ? 3600
            : cachedClient.AccessTokenExpiration;

        var tokenType = request.Jkt is null
            ? TokenTypeSchemaConstants.Bearer
            : TokenTypeSchemaConstants.DPoP;

        return new TokenResponse
        {
            AccessToken = token,
            ExpiresIn = expiresIn,
            TokenType = tokenType,
            IssuedTokenType = request.RequestedTokenType,
            GrantId = request.SubjectToken.GrantId,
            Scope = request.Scope.Count == 0 ? null : string.Join(' ', request.Scope)
        };
    }
}