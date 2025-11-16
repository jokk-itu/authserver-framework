namespace AuthServer.TokenBuilders;
internal class IdTokenArguments
{
    public required string AuthorizationGrantId { get; init; }
    public required IReadOnlyCollection<string> Scope { get; init; }
    public string? SubjectActor { get; init; }
    public string? EncyptorClientId { get; init; }
}