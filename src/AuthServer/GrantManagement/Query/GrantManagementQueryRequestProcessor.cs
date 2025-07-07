using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Extensions;
using AuthServer.Repositories.Abstractions;

namespace AuthServer.GrantManagement.Query;
internal class GrantManagementQueryRequestProcessor : IRequestProcessor<GrantManagementValidatedRequest, GrantResponse>
{
    private readonly IConsentRepository _consentRepository;
    private readonly AuthorizationDbContext _authorizationDbContext;

    public GrantManagementQueryRequestProcessor(IConsentRepository consentRepository, AuthorizationDbContext authorizationDbContext)
    {
        _consentRepository = consentRepository;
        _authorizationDbContext = authorizationDbContext;
    }

    public async Task<GrantResponse> Process(GrantManagementValidatedRequest request, CancellationToken cancellationToken)
    {
        var grant = (await _authorizationDbContext.FindAsync<AuthorizationGrant>([request.GrantId], cancellationToken))!;
        var consents = await _consentRepository.GetGrantConsents(request.GrantId, cancellationToken);

        var claims = consents
            .Select(x => x.Consent)
            .OfType<ClaimConsent>()
            .Select(x => x.Claim)
            .Select(x => x.Name)
            .ToList();

        var scopeDtos = consents
            .OfType<AuthorizationGrantScopeConsent>()
            .GroupBy(x => x.Resource)
            .Select(x => new ScopeDto
            {
                Resources = [x.Key],
                Scopes = x
                    .Select(y => y.Consent)
                    .OfType<ScopeConsent>()
                    .Select(y => y.Scope)
                    .Select(y => y.Name)
                    .ToList()
            })
            .ToList();

        return new GrantResponse
        {
            Scopes = scopeDtos,
            Claims = claims,
            CreatedAt = grant.CreatedAuthTime.ToUnixTimeSeconds(),
            UpdatedAt = grant.UpdatedAuthTime.ToUnixTimeSeconds()
        };
    }
}