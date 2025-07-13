using AuthServer.Cache.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.TokenBuilders;
using AuthServer.TokenBuilders.Abstractions;

namespace AuthServer.TokenByGrant.TokenDeviceCodeGrant;
internal class DeviceCodeRequestProcessor : IRequestProcessor<DeviceCodeValidatedRequest, TokenResponse>
{
    private readonly AuthorizationDbContext _authorizationDbContext;
    private readonly ITokenBuilder<IdTokenArguments> _idTokenBuilder;
    private readonly ITokenBuilder<GrantAccessTokenArguments> _accessTokenBuilder;
    private readonly ITokenBuilder<RefreshTokenArguments> _refreshTokenBuilder;
    private readonly ICachedClientStore _cachedClientStore;

    public DeviceCodeRequestProcessor(
        AuthorizationDbContext authorizationDbContext,
        ITokenBuilder<IdTokenArguments> idTokenBuilder,
        ITokenBuilder<GrantAccessTokenArguments> accessTokenBuilder,
        ITokenBuilder<RefreshTokenArguments> refreshTokenBuilder,
        ICachedClientStore cachedClientStore)
    {
        _authorizationDbContext = authorizationDbContext;
        _idTokenBuilder = idTokenBuilder;
        _accessTokenBuilder = accessTokenBuilder;
        _refreshTokenBuilder = refreshTokenBuilder;
        _cachedClientStore = cachedClientStore;
    }

    public async Task<TokenResponse> Process(DeviceCodeValidatedRequest request, CancellationToken cancellationToken)
    {
        var deviceCode = (await _authorizationDbContext.FindAsync<DeviceCode>([request.DeviceCodeId], cancellationToken))!;
        deviceCode.Redeem();

        var cachedClient = await _cachedClientStore.Get(request.ClientId, cancellationToken);

        string? refreshToken = null;
        if (cachedClient.GrantTypes.Any(x => x == GrantTypeConstants.RefreshToken))
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
