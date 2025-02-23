namespace AuthServer.Introspection;
internal class IntrospectionValidatedRequest
{
    public required string Token { get; init; }
    public required IReadOnlyCollection<string> Scope { get; init; }
}