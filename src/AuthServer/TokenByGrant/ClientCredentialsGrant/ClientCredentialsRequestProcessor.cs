using AuthServer.Cache.Abstractions;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.TokenBuilders;
using AuthServer.TokenBuilders.Abstractions;

namespace AuthServer.TokenByGrant.ClientCredentialsGrant;

internal class ClientCredentialsRequestProcessor : IRequestProcessor<ClientCredentialsValidatedRequest, TokenResponse>
{
    private readonly ITokenBuilder<ClientAccessTokenArguments> _tokenBuilder;
    private readonly ICachedClientStore _cachedClientStore;

    public ClientCredentialsRequestProcessor(
        ITokenBuilder<ClientAccessTokenArguments> tokenBuilder,
        ICachedClientStore cachedClientStore)
    {
        _tokenBuilder = tokenBuilder;
        _cachedClientStore = cachedClientStore;
    }

    public async Task<TokenResponse> Process(ClientCredentialsValidatedRequest request, CancellationToken cancellationToken)
    {
        var cachedClient = await _cachedClientStore.Get(request.ClientId, cancellationToken);
        var accessToken = await _tokenBuilder.BuildToken(new ClientAccessTokenArguments
        {
            ClientId = request.ClientId,
            Jkt = request.DPoPJkt,
            Resource = request.Resource,
            Scope = request.Scope
        }, cancellationToken);

        var tokenType = string.IsNullOrEmpty(request.DPoPJkt)
            ? TokenTypeSchemaConstants.Bearer
            : TokenTypeSchemaConstants.DPoP;

        return new TokenResponse
        {
            AccessToken = accessToken,
            Scope = string.Join(' ', request.Scope),
            ExpiresIn = cachedClient.AccessTokenExpiration,
            TokenType = tokenType
        };
    }
}