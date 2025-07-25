namespace AuthServer.TokenByGrant.TokenRefreshTokenGrant;
internal class RefreshTokenValidatedRequest
{
    public required string ClientId { get; init; }
    public required string AuthorizationGrantId { get; init; }
    public string? DPoPJkt { get; init; }
    public required IReadOnlyCollection<string> Scope { get; init; }
    public required IReadOnlyCollection<string> Resource { get; init; }
}