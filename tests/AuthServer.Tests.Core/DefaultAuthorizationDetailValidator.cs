using System.Text.Json;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Repositories.Models;

namespace AuthServer.Tests.Core;

public class DefaultAuthorizationDetailValidator : IAuthorizationDetailValidator
{
    public Task<AuthorizationDetailDto?> ValidateAuthorizationDetail(string authorizationDetail, CancellationToken cancellationToken)
    {
        try
        {
            return Task.FromResult<AuthorizationDetailDto?>(JsonSerializer.Deserialize<DefaultAuthorizationDetailDto>(authorizationDetail));
        }
        catch (Exception)
        {
            return Task.FromResult<AuthorizationDetailDto?>(null);
        }
    }

    public Task<bool> ValidateAuthorizationDetail(string authorizationDetail, IReadOnlyCollection<string> grantAuthorizationDetails,
        CancellationToken cancellationToken)
    {
        try
        {
            return Task.FromResult(true);
        }
        catch (Exception)
        {
            return Task.FromResult(false);
        }
    }
}