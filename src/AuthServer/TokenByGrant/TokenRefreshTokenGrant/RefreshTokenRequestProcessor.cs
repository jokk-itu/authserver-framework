using AuthServer.Cache.Abstractions;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.TokenBuilders;
using AuthServer.TokenBuilders.Abstractions;

namespace AuthServer.TokenByGrant.TokenRefreshTokenGrant;

internal class RefreshTokenRequestProcessor : IRequestProcessor<RefreshTokenValidatedRequest, TokenResponse>
{
    private readonly ITokenBuilder<GrantAccessTokenArguments> _accessTokenBuilder;
    private readonly ITokenBuilder<IdTokenArguments> _idTokenBuilder;
    private readonly ICachedClientStore _cachedEntityStore;

    public RefreshTokenRequestProcessor(
        ITokenBuilder<GrantAccessTokenArguments> accessTokenBuilder,
        ITokenBuilder<IdTokenArguments> idTokenBuilder,
        ICachedClientStore cachedEntityStore)
    {
        _accessTokenBuilder = accessTokenBuilder;
        _idTokenBuilder = idTokenBuilder;
        _cachedEntityStore = cachedEntityStore;
    }

    public async Task<TokenResponse> Process(RefreshTokenValidatedRequest request, CancellationToken cancellationToken)
    {
        var cachedClient = await _cachedEntityStore.Get(request.ClientId, cancellationToken);
        var accessToken = await _accessTokenBuilder.BuildToken(new GrantAccessTokenArguments
        {
            AuthorizationGrantId = request.AuthorizationGrantId,
            Jkt = request.DPoPJkt,
            Resource = request.Resource,
            Scope = request.Scope
        }, cancellationToken);

        var idToken = await _idTokenBuilder.BuildToken(new IdTokenArguments
        {
            AuthorizationGrantId = request.AuthorizationGrantId,
            Scope = request.Scope
        }, cancellationToken);

        var tokenType = string.IsNullOrEmpty(request.DPoPJkt)
            ? TokenTypeSchemaConstants.Bearer
            : TokenTypeSchemaConstants.DPoP;

        return new TokenResponse
        {
            AccessToken = accessToken,
            IdToken = idToken,
            ExpiresIn = cachedClient.AccessTokenExpiration,
            Scope = string.Join(' ', request.Scope),
            GrantId = request.AuthorizationGrantId,
            TokenType = tokenType
        };
    }
}