namespace AuthServer.Core.Abstractions;

internal interface IUnitOfWork
{
    Task Begin(CancellationToken cancellationToken);
    Task SaveChanges(CancellationToken cancellationToken);
    Task Commit(CancellationToken cancellationToken);
}