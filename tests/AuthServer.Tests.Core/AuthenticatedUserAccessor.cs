using AuthServer.Authentication.Abstractions;
using AuthServer.Authentication.Models;

namespace AuthServer.Tests.Core;
public class AuthenticatedUserAccessor : IAuthenticatedUserAccessor
{
    public Task<AuthenticatedUser?> GetAuthenticatedUser()
    {
        return Task.FromResult<AuthenticatedUser?>(
            new AuthenticatedUser(UserConstants.SubjectIdentifier, Guid.NewGuid().ToString()));
    }

    public Task<int> CountAuthenticatedUsers()
    {
        return Task.FromResult(0);
    }
}
