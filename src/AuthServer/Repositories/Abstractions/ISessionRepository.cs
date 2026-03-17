namespace AuthServer.Repositories.Abstractions;
internal interface ISessionRepository
{
    /// <summary>
    /// Revokes session if active, with all relations.
    /// </summary>
    /// <param name="sessionId"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task RevokeSession(string sessionId, CancellationToken cancellationToken);

    /// <summary>
    /// Revokes inactive sessions, based on <paramref name="batchSize"/>.
    /// </summary>
    /// <param name="batchSize"></param>
    /// <param name="cancellationToken"></param>
    /// <returns></returns>
    Task RevokeExpiredSessions(int batchSize, CancellationToken cancellationToken);

    /// <summary>
    /// Get the active session of the subject, if it exists.
    /// </summary>
    /// <param name="subjectIdentifier"></param>
    /// <param name="cancellationToken"></param>
    /// <returns>The active session of the end user or null</returns>
    Task<string?> GetActiveSessionId(string subjectIdentifier, CancellationToken cancellationToken);
}
