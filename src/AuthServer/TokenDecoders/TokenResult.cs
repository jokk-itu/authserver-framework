namespace AuthServer.TokenDecoders;
internal class TokenResult
{
    public required string Jti { get; init; }
    public required string ClientId { get; init; }
    public required string Subject { get; init; }
    public required string Typ { get; init; }
    public required IReadOnlyCollection<string> Scope { get; init; }
    public string? GrantId { get; init; }
    public string? Sid { get; init; }
    public string? Jkt { get; init; }
}