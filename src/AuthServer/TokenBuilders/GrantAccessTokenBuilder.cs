using System.Diagnostics;
using System.Text.Json;
using AuthServer.Authentication.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Extensions;
using AuthServer.Metrics;
using AuthServer.Metrics.Abstractions;
using AuthServer.Options;
using AuthServer.TokenBuilders.Abstractions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.TokenBuilders;

internal class GrantAccessTokenBuilder : ITokenBuilder<GrantAccessTokenArguments>
{
    private readonly AuthorizationDbContext _identityContext;
    private readonly IOptionsSnapshot<DiscoveryDocument> _discoveryDocumentOptions;
    private readonly IOptionsSnapshot<JwksDocument> _jwksDocument;
    private readonly IMetricService _metricService;
    private readonly IUserClaimService _userClaimService;

    public GrantAccessTokenBuilder(
        AuthorizationDbContext identityContext,
        IOptionsSnapshot<DiscoveryDocument> discoveryDocumentOptions,
        IOptionsSnapshot<JwksDocument> jwksDocument,
        IMetricService metricService,
        IUserClaimService userClaimService)
    {
        _identityContext = identityContext;
        _discoveryDocumentOptions = discoveryDocumentOptions;
        _jwksDocument = jwksDocument;
        _metricService = metricService;
        _userClaimService = userClaimService;
    }

    public async Task<string> BuildToken(GrantAccessTokenArguments arguments, CancellationToken cancellationToken)
    {
        var stopWatch = Stopwatch.StartNew();
        var grantQuery = await _identityContext
            .Set<AuthorizationGrant>()
            .Where(x => x.Id == arguments.AuthorizationGrantId)
            .Select(x => new GrantQuery
            {
                AuthorizationGrant = x,
                Client = x.Client,
                Subject = x.Subject,
                SubjectIdentifier = x.Session.SubjectIdentifier.Id,
                SessionId = x.Session.Id,
                Acr = x.AuthenticationContextReference.Name
            })
            .SingleAsync(cancellationToken);

        if (grantQuery.Client.RequireReferenceToken)
        {
            var referenceToken = await BuildReferenceToken(arguments, grantQuery);
            stopWatch.Stop();
            _metricService.AddBuiltToken(stopWatch.ElapsedMilliseconds, TokenTypeTag.AccessToken, TokenStructureTag.Reference);
            return referenceToken;
        }

        var jwt = await BuildStructuredToken(arguments, grantQuery, cancellationToken);
        stopWatch.Stop();
        _metricService.AddBuiltToken(stopWatch.ElapsedMilliseconds, TokenTypeTag.AccessToken, TokenStructureTag.Jwt);
        return jwt;
    }

    private async Task<string> BuildStructuredToken(GrantAccessTokenArguments arguments, GrantQuery grantQuery, CancellationToken cancellationToken)
    {
        var accessControl = (await _userClaimService.GetAccessClaims(grantQuery.SubjectIdentifier, cancellationToken))
            .ToDictionary(x => x.Type, x => JsonSerializer.SerializeToElement(x.Value));

        var claims = new Dictionary<string, object>
        {
            { ClaimNameConstants.Jti, Guid.NewGuid() },
            { ClaimNameConstants.Scope, string.Join(' ', arguments.Scope) },
            { ClaimNameConstants.Aud, JsonSerializer.SerializeToElement(arguments.Resource) },
            { ClaimNameConstants.GrantId, arguments.AuthorizationGrantId },
            { ClaimNameConstants.Sub, grantQuery.Subject },
            { ClaimNameConstants.Sid, grantQuery.SessionId },
            { ClaimNameConstants.ClientId, grantQuery.Client.Id },
            { ClaimNameConstants.AuthTime, grantQuery.AuthorizationGrant.AuthTime.ToUnixTimeSeconds() },
            { ClaimNameConstants.Acr, grantQuery.Acr },
            { ClaimNameConstants.AccessControl, accessControl }
        };

        var now = DateTime.UtcNow;
        var signingKey = _jwksDocument.Value.GetTokenSigningKey();
        var signingCredentials = new SigningCredentials(signingKey.Key, signingKey.Alg.GetDescription());

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            IssuedAt = now,
            Expires = now.AddSeconds(grantQuery.Client.AccessTokenExpiration),
            NotBefore = now,
            Issuer = _discoveryDocumentOptions.Value.Issuer,
            SigningCredentials = signingCredentials,
            TokenType = TokenTypeHeaderConstants.AccessToken,
            Claims = claims
        };
        var tokenHandler = new JsonWebTokenHandler();
        return tokenHandler.CreateToken(tokenDescriptor);
    }

    private async Task<string> BuildReferenceToken(GrantAccessTokenArguments arguments, GrantQuery grantQuery)
    {
        var accessToken = new GrantAccessToken(grantQuery.AuthorizationGrant,
            string.Join(' ', arguments.Resource), _discoveryDocumentOptions.Value.Issuer,
            string.Join(' ', arguments.Scope), grantQuery.Client.AccessTokenExpiration);

        await _identityContext.Set<GrantAccessToken>().AddAsync(accessToken);
        return accessToken.Reference;
    }

    private sealed class GrantQuery
    {
        public required AuthorizationGrant AuthorizationGrant { get; init; }
        public required Client Client { get; init; }
        public required string SessionId { get; init; }
        public required string Subject { get; init; }
        public required string SubjectIdentifier { get; init; }
        public required string Acr { get; init; }
    }
}