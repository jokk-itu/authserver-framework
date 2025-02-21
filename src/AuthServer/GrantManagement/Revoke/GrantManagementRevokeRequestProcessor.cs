using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Repositories.Abstractions;

namespace AuthServer.GrantManagement.Revoke;

internal class GrantManagementRevokeRequestProcessor : IRequestProcessor<GrantManagementValidatedRequest, Unit>
{
    private readonly IAuthorizationGrantRepository _authorizationGrantRepository;

    public GrantManagementRevokeRequestProcessor(IAuthorizationGrantRepository authorizationGrantRepository)
    {
        _authorizationGrantRepository = authorizationGrantRepository;
    }
    
    public async Task<Unit> Process(GrantManagementValidatedRequest request, CancellationToken cancellationToken)
    {
        await _authorizationGrantRepository.RevokeGrant(request.GrantId, cancellationToken);
        return Unit.Value;
    }
}