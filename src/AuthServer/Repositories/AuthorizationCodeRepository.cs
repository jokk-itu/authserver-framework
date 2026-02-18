using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Options;
using AuthServer.Repositories.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.Repositories;

internal class AuthorizationCodeRepository : IAuthorizationCodeRepository
{
    private readonly AuthorizationDbContext _authorizationDbContext;
    private readonly IOptionsMonitor<TokenValidationOptions> _tokenValidatíonOptions;
    private readonly ILogger<AuthorizationCodeRepository> _logger;

    public AuthorizationCodeRepository(
        AuthorizationDbContext authorizationDbContext,
        IOptionsMonitor<TokenValidationOptions> tokenValidatíonOptions,
        ILogger<AuthorizationCodeRepository> logger)
    {
        _authorizationDbContext = authorizationDbContext;
        _tokenValidatíonOptions = tokenValidatíonOptions;
        _logger = logger;
    }

    public async Task<bool> IsActiveAuthorizationCode(string authorizationCodeId, CancellationToken cancellationToken)
    {
        var code = await _authorizationDbContext
            .Set<AuthorizationCode>()
            .SingleOrDefaultAsync(x => x.Id == authorizationCodeId, cancellationToken);

        if (code is null)
        {
            _logger.LogDebug("Code with id {AuthorizationCodeId} does not exist", authorizationCodeId);
            return false;
        }

        if (code.RedeemedAt is not null)
        {
            _logger.LogDebug("Code with id {AuthorizationCodeId} has been redeemed at {RedeemedAt}", authorizationCodeId, code.RedeemedAt);
            return false;
        }

        if (code.ExpiresAt.Add(_tokenValidatíonOptions.CurrentValue.ClockSkew) < DateTime.UtcNow)
        {
            _logger.LogDebug("Code with id {AuthorizationCodeId} expired at {ExpiresAt}", authorizationCodeId, code.ExpiresAt);
            return false;
        }

        return true;
    }
}