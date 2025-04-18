using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Repositories.Abstractions;
using Microsoft.EntityFrameworkCore;
using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace AuthServer.Repositories;

internal class TokenRepository : ITokenRepository
{
	private readonly AuthorizationDbContext _authorizationDbContext;
    private readonly ILogger<TokenRepository> _logger;

    public TokenRepository(
        AuthorizationDbContext authorizationDbContext,
        ILogger<TokenRepository> logger)
    {
        _authorizationDbContext = authorizationDbContext;
        _logger = logger;
    }

	/// <inheritdoc/>
	public async Task<RegistrationToken?> GetActiveRegistrationToken(string registrationAccessToken, CancellationToken cancellationToken)
	{
		return await _authorizationDbContext
			.Set<RegistrationToken>()
			.Where(t => t.Reference == registrationAccessToken)
			.Where(Token.IsActive)
			.OfType<RegistrationToken>()
			.Include(t => t.Client)
			.SingleOrDefaultAsync(cancellationToken);
	}

    /// <inheritdoc/>
    public async Task RevokeExpiredTokens(int batchSize, CancellationToken cancellationToken)
    {
        var timer = Stopwatch.StartNew();

        var affectedTokens = await _authorizationDbContext
            .Set<Token>()
            .Where(Token.IsExpired)
            .Take(batchSize)
            .ExecuteDeleteAsync(cancellationToken);

        timer.Stop();

        _logger.LogInformation(
            "Revoked {Amount} tokens in {ElapsedTime} milliseconds",
            affectedTokens,
            timer.ElapsedMilliseconds);
    }
}