namespace AuthServer.TokenBuilders;
internal class ClientAccessTokenArguments
{
    public required string ClientId { get; init; }
    public string? Jkt { get; init; }
    public required IReadOnlyCollection<string> Resource { get; init; }
    public required IReadOnlyCollection<string> Scope { get; init; }
}