using AuthServer.Cache.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.TokenBuilders;
using AuthServer.TokenBuilders.Abstractions;

namespace AuthServer.TokenByGrant.TokenAuthorizationCodeGrant;
internal class AuthorizationCodeRequestProcessor : IRequestProcessor<AuthorizationCodeValidatedRequest, TokenResponse>
{
    private readonly AuthorizationDbContext _identityContext;
    private readonly ICachedClientStore _cachedClientStore;
    private readonly ITokenBuilder<GrantAccessTokenArguments> _accessTokenBuilder;
    private readonly ITokenBuilder<RefreshTokenArguments> _refreshTokenBuilder;
    private readonly ITokenBuilder<IdTokenArguments> _idTokenBuilder;

    public AuthorizationCodeRequestProcessor(
        AuthorizationDbContext identityContext,
        ICachedClientStore cachedClientStore,
        ITokenBuilder<GrantAccessTokenArguments> accessTokenBuilder,
        ITokenBuilder<RefreshTokenArguments> refreshTokenBuilder,
        ITokenBuilder<IdTokenArguments> idTokenBuilder)
    {
        _identityContext = identityContext;
        _cachedClientStore = cachedClientStore;
        _accessTokenBuilder = accessTokenBuilder;
        _refreshTokenBuilder = refreshTokenBuilder;
        _idTokenBuilder = idTokenBuilder;
    }

    public async Task<TokenResponse> Process(AuthorizationCodeValidatedRequest request,
        CancellationToken cancellationToken)
    {
        var authorizationCode = (await _identityContext.FindAsync<AuthorizationCode>([request.AuthorizationCodeId], cancellationToken))!;
        authorizationCode.Redeem();

        var cachedClient = await _cachedClientStore.Get(request.ClientId, cancellationToken);

        string? refreshToken = null;
        if (cachedClient.GrantTypes.Any(x => x == GrantTypeConstants.RefreshToken)
            && request.Scope.Contains(ScopeConstants.OfflineAccess))
        {
            refreshToken = await _refreshTokenBuilder.BuildToken(new RefreshTokenArguments
            {
                AuthorizationGrantId = request.AuthorizationGrantId,
                Jkt = cachedClient.TokenEndpointAuthMethod == TokenEndpointAuthMethod.None
                    ? request.DPoPJkt : null,
                Scope = request.Scope
            }, cancellationToken);
        }

        var accessToken = await _accessTokenBuilder.BuildToken(new GrantAccessTokenArguments
        {
            AuthorizationGrantId = request.AuthorizationGrantId,
            Jkt = request.DPoPJkt,
            Scope = request.Scope,
            Resource = request.Resource
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
            RefreshToken = refreshToken,
            ExpiresIn = cachedClient.AccessTokenExpiration,
            Scope = string.Join(' ', request.Scope),
            GrantId = request.AuthorizationGrantId,
            TokenType = tokenType
        };
    }
}