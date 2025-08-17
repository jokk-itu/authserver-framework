using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Entities;
using AuthServer.Metrics;
using AuthServer.Metrics.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.Revocation;
internal class RevocationRequestProcessor : IRequestProcessor<RevocationValidatedRequest, Unit>
{
    private readonly AuthorizationDbContext _identityContext;
    private readonly IMetricService _metricService;

    public RevocationRequestProcessor(
        AuthorizationDbContext identityContext,
        IMetricService metricService)
    {
        _identityContext = identityContext;
        _metricService = metricService;
    }

    public async Task<Unit> Process(RevocationValidatedRequest request, CancellationToken cancellationToken)
    {
        var token = await GetToken(request, cancellationToken);
        if (token is not null)
        {
            _metricService.AddRevokedToken(token is RefreshToken ? TokenTypeTag.RefreshToken : TokenTypeTag.AccessToken);
            token.Revoke();
        }

        return Unit.Value;
    }

    private async Task<Token?> GetToken(RevocationValidatedRequest request, CancellationToken cancellationToken)
    {
        if (request.Jti is null)
        {
            return null;
        }

        var id = Guid.Parse(request.Jti);
        return await _identityContext
            .Set<Token>()
            .Where(x => x.RevokedAt == null)
            .SingleOrDefaultAsync(x => x.Id == id, cancellationToken: cancellationToken);
    }
}