using System.Text.Json;
using AuthServer.Authentication.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Extensions;
using AuthServer.Metrics;
using AuthServer.Metrics.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.Introspection;
internal class IntrospectionRequestProcessor : IRequestProcessor<IntrospectionValidatedRequest, IntrospectionResponse>
{
    private readonly AuthorizationDbContext _identityContext;
    private readonly IUserClaimService _userClaimService;
    private readonly IMetricService _metricService;

    public IntrospectionRequestProcessor(
        AuthorizationDbContext identityContext,
        IUserClaimService userClaimService,
        IMetricService metricService)
    {
        _identityContext = identityContext;
        _userClaimService = userClaimService;
        _metricService = metricService;
    }

    public async Task<IntrospectionResponse> Process(IntrospectionValidatedRequest request, CancellationToken cancellationToken)
    {
        var query = await _identityContext
            .Set<Token>()
            .Where(x => x.Reference == request.Token)
            .Select(x => new TokenQuery
            {
                Token = x,
                ClientIdFromClientAccessToken = (x as ClientAccessToken)!.Client.Id,
                ClientIdFromGrantAccessToken = (x as GrantAccessToken)!.AuthorizationGrant.Client.Id,
                SubjectFromGrantToken = (x as GrantToken)!.AuthorizationGrant.Subject,
                SubjectFromClientToken = (x as ClientAccessToken)!.Client.Id,
                SubjectIdentifier = (x as GrantToken)!.AuthorizationGrant.Session.SubjectIdentifier.Id,
                AuthTime = (x as GrantToken)!.AuthorizationGrant.UpdatedAuthTime,
                Acr = (x as GrantAccessToken)!.AuthorizationGrant.AuthenticationContextReference.Name
            })
            .SingleOrDefaultAsync(cancellationToken: cancellationToken);

        var isInvalidToken = query is null;
        var hasExceededExpiration = query?.Token.ExpiresAt < DateTime.UtcNow;
        var isRevoked = query?.Token.RevokedAt is not null;
        var scope = query?.Token.Scope?.Split(' ') ?? [];
        var authorizedScope = request.Scope.Intersect(scope).ToList();

        /*
         * If active is false, then the requesting client does not need to know more.
         * Therefore, the other optional properties are not set.
         */
        if (isInvalidToken || hasExceededExpiration || isRevoked || authorizedScope.Count == 0)
        {
            return new IntrospectionResponse
            {
                Active = false
            };
        }

        var token = query!.Token;
        string? username = null;
        if (query.SubjectIdentifier is not null)
        {
            username = await _userClaimService.GetUsername(query.SubjectIdentifier, cancellationToken);
        }

        var subject = query.SubjectFromGrantToken ?? query.SubjectFromClientToken;

        IDictionary<string, object>? accessControl = null;
        if (query.SubjectIdentifier is not null)
        {
            accessControl = (await _userClaimService.GetAccessClaims(query.SubjectIdentifier, cancellationToken))
                .ToDictionary(x => x.Type, x => JsonSerializer.SerializeToElement(x.Value) as object);
        }

        _metricService.AddIntrospectedToken(query.Token is RefreshToken
            ? TokenTypeTag.RefreshToken
            : TokenTypeTag.AccessToken);

        var tokenType = string.IsNullOrEmpty(query.Token.Jkt)
            ? TokenTypeSchemaConstants.Bearer
            : TokenTypeSchemaConstants.DPoP;

        return new IntrospectionResponse
        {
            Active = token.RevokedAt is null,
            JwtId = token.Id.ToString(),
            ClientId = query.ClientIdFromClientAccessToken ?? query.ClientIdFromGrantAccessToken,
            ExpiresAt = token.ExpiresAt?.ToUnixTimeSeconds(),
            Issuer = token.Issuer,
            Audience = token.Audience.Split(' '),
            IssuedAt = token.IssuedAt.ToUnixTimeSeconds(),
            NotBefore = token.NotBefore.ToUnixTimeSeconds(),
            Scope = string.Join(' ', authorizedScope),
            Subject = subject,
            TokenType = tokenType,
            Username = username,
            AuthTime = query.AuthTime?.ToUnixTimeSeconds(),
            Acr = query.Acr,
            AccessControl = accessControl
        };
    }

    private sealed class TokenQuery
    {
        public required Token Token { get; init; }
        public string? ClientIdFromClientAccessToken { get; init; }
        public string? ClientIdFromGrantAccessToken { get; init; }
        public string? SubjectFromGrantToken { get; init; }
        public string? SubjectFromClientToken { get; init; }
        public string? SubjectIdentifier { get; init; }
        public DateTime? AuthTime { get; init; }
        public string? Acr { get; init; }
    }
}