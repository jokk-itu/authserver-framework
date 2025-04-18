namespace AuthServer.Options;
public class CleanupOptions
{
    public bool RunSessionCleanup { get; set; }
    public int SessionCleanupIntervalInSeconds { get; set; }
    public int SessionCleanupBatchSize { get; set; }

    public bool RunAuthorizationGrantCleanup { get; set; }
    public int AuthorizationGrantCleanupIntervalInSeconds { get; set; }
    public int AuthorizationGrantCleanupBatchSize { get; set; }

    public bool RunTokenCleanup { get; set; }
    public int RunTokenCleanupIntervalInSeconds { get; set; }
    public int RunTokenCleanupBatchSize { get; set; }
}