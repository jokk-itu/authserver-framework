namespace AuthServer.TokenBuilders;
internal class GrantAccessTokenArguments
{
    public required string AuthorizationGrantId { get; init; }
    public string? Jkt { get; init; }
    public string? SubjectActor { get; init; }
    public required IReadOnlyCollection<string> Resource { get; init; }
    public required IReadOnlyCollection<string> Scope { get; init; }
}