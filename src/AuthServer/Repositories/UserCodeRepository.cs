using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Repositories.Abstractions;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.Repositories;

internal class UserCodeRepository : IUserCodeRepository
{
    private readonly AuthorizationDbContext _authorizationDbContext;

    public UserCodeRepository(
        AuthorizationDbContext authorizationDbContext)
    {
        _authorizationDbContext = authorizationDbContext;
    }

    public async Task RedeemUserCode(string userCode, CancellationToken cancellationToken)
    {
        var userCodeEntity = await _authorizationDbContext
            .Set<UserCode>()
            .Where(uc => uc.Value == userCode)
            .SingleAsync(cancellationToken);

        userCodeEntity.Redeem();

        await _authorizationDbContext.SaveChangesAsync(cancellationToken);
    }
}