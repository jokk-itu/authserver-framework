using System.Diagnostics;
using AuthServer.Cache.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Extensions;
using AuthServer.Metrics;
using AuthServer.Metrics.Abstractions;
using AuthServer.Options;
using AuthServer.TokenBuilders.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.TokenBuilders;

internal class LogoutTokenBuilder : ITokenBuilder<LogoutTokenArguments>
{
    private readonly IOptionsSnapshot<DiscoveryDocument> _discoveryDocumentOptions;
    private readonly IOptionsSnapshot<JwksDocument> _jwksDocumentOptions;
    private readonly ITokenSecurityService _tokenSecurityService;
    private readonly IMetricService _metricService;
    private readonly AuthorizationDbContext _authorizationDbContext;

    public LogoutTokenBuilder(
        IOptionsSnapshot<DiscoveryDocument> discoveryDocumentOptions,
        IOptionsSnapshot<JwksDocument> jwksDocumentOptions,
        ITokenSecurityService tokenSecurityService,
        IMetricService metricService,
        AuthorizationDbContext authorizationDbContext)
    {
        _discoveryDocumentOptions = discoveryDocumentOptions;
        _jwksDocumentOptions = jwksDocumentOptions;
        _tokenSecurityService = tokenSecurityService;
        _metricService = metricService;
        _authorizationDbContext = authorizationDbContext;
    }

    public async Task<string> BuildToken(LogoutTokenArguments arguments, CancellationToken cancellationToken)
    {
        var stopWatch = Stopwatch.StartNew();
        var client = (await _authorizationDbContext.FindAsync<Client>([arguments.ClientId], cancellationToken))!;
        var claims = new Dictionary<string, object?>
        {
            { ClaimNameConstants.Aud, arguments.ClientId },
            { ClaimNameConstants.Sid, arguments.SessionId },
            { ClaimNameConstants.Sub, arguments.SubjectIdentifier },
            { ClaimNameConstants.Jti, Guid.NewGuid() },
            { ClaimNameConstants.ClientId, arguments.ClientId },
            {
                ClaimNameConstants.Events, new Dictionary<string, object>
                {
                    { "http://schemas.openid.net/event/backchannel-logout", new Dictionary<string, object>() }
                }
            }
        };

        var now = DateTime.UtcNow;
        var signingKey = _jwksDocumentOptions.Value.GetSigningKey(client.IdTokenSignedResponseAlg!.Value);
        var signingCredentials =
            new SigningCredentials(signingKey, client.IdTokenSignedResponseAlg.GetDescription());

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            IssuedAt = now,
            Expires = now.AddSeconds(60),
            NotBefore = now,
            Issuer = _discoveryDocumentOptions.Value.Issuer,
            SigningCredentials = signingCredentials,
            TokenType = TokenTypeHeaderConstants.LogoutToken,
            Claims = claims
        };

        if (client.IdTokenEncryptedResponseAlg is not null &&
            client.IdTokenEncryptedResponseEnc is not null)
        {
            tokenDescriptor.EncryptingCredentials = await _tokenSecurityService.GetEncryptingCredentials(
                arguments.ClientId,
                client.IdTokenEncryptedResponseAlg.Value,
                client.IdTokenEncryptedResponseEnc.Value,
                cancellationToken);
        }

        var tokenHandler = new JsonWebTokenHandler();
        var jwt = tokenHandler.CreateToken(tokenDescriptor);
        _metricService.AddBuiltToken(stopWatch.ElapsedMilliseconds, TokenTypeTag.LogoutToken, TokenStructureTag.Jwt);
        return jwt;
    }
}