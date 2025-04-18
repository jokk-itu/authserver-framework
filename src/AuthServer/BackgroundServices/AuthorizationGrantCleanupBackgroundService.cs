using AuthServer.Core.Abstractions;
using AuthServer.Options;
using AuthServer.Repositories.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AuthServer.BackgroundServices;
internal class AuthorizationGrantCleanupBackgroundService : BackgroundService
{
    private readonly IServiceProvider _globalServiceProvider;
    private readonly IOptionsMonitor<CleanupOptions> _cleanupOptions;
    private readonly ILogger<AuthorizationGrantCleanupBackgroundService> _logger;

    public AuthorizationGrantCleanupBackgroundService(
        IServiceProvider globalServiceProvider,
        IOptionsMonitor<CleanupOptions> cleanupOptions,
        ILogger<AuthorizationGrantCleanupBackgroundService> logger)
    {
        _globalServiceProvider = globalServiceProvider;
        _cleanupOptions = cleanupOptions;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Set default value, as the Cleanup might be disabled.
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));

        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            var current = _cleanupOptions.CurrentValue;
            if (!current.RunAuthorizationGrantCleanup)
            {
                await Task.Delay(10000, stoppingToken);
                continue;
            }

            timer.Period = TimeSpan.FromSeconds(current.AuthorizationGrantCleanupIntervalInSeconds);

            try
            {
                await Revoke(current, stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Unexpected error occurred. Retrying cleanup.");
            }
        }
    }

    private async Task Revoke(CleanupOptions cleanupOptions, CancellationToken stoppingToken)
    {
        await using var serviceScope = _globalServiceProvider.CreateAsyncScope();
        var unitOfWork = serviceScope.ServiceProvider.GetRequiredService<IUnitOfWork>();
        var authorizationGrantRepository = serviceScope.ServiceProvider.GetRequiredService<IAuthorizationGrantRepository>();

        await unitOfWork.Begin(stoppingToken);
        await authorizationGrantRepository.RevokeExpiredGrants(cleanupOptions.AuthorizationGrantCleanupBatchSize, stoppingToken);
        await unitOfWork.Commit(stoppingToken);
    }
}