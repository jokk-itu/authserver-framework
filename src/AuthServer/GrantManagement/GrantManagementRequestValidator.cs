using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Entities;
using AuthServer.TokenDecoders.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.GrantManagement;

internal class GrantManagementRequestValidator : IRequestValidator<GrantManagementRequest, GrantManagementValidatedRequest>
{
    private readonly AuthorizationDbContext _authorizationDbContext;
    private readonly IServerTokenDecoder _serverTokenDecoder;

    public GrantManagementRequestValidator(
        AuthorizationDbContext authorizationDbContext,
        IServerTokenDecoder serverTokenDecoder)
    {
        _authorizationDbContext = authorizationDbContext;
        _serverTokenDecoder = serverTokenDecoder;
    }
    
    public async Task<ProcessResult<GrantManagementValidatedRequest, ProcessError>> Validate(GrantManagementRequest request, CancellationToken cancellationToken)
    {
        if (request.GrantId is null)
        {
            return GrantManagementError.InvalidGrantId;
        }

        var clientIdFromGrant = await _authorizationDbContext
            .Set<AuthorizationGrant>()
            .Where(AuthorizationGrant.IsActive)
            .Where(x => x.Id == request.GrantId)
            .Select(x => x.Client.Id)
            .SingleOrDefaultAsync(cancellationToken);

        if (clientIdFromGrant is null)
        {
            return GrantManagementError.NotFoundGrantId;
        }

        var tokenResult = await _serverTokenDecoder.Read(request.AccessToken, cancellationToken);

        if (clientIdFromGrant != tokenResult.ClientId)
        {
            return GrantManagementError.InvalidGrant;
        }
        
        return new GrantManagementValidatedRequest
        { 
            GrantId = request.GrantId!
        };
    }
}