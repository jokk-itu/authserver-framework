namespace AuthServer.TokenByGrant.TokenClientCredentialsGrant;
internal class ClientCredentialsValidatedRequest
{
    public required string ClientId { get; init; }
    public string? DPoPJkt { get; init; }
    public required IReadOnlyCollection<string> Resource { get; init; }
    public required IReadOnlyCollection<string> Scope { get; init; }
}