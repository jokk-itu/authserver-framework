namespace AuthServer.TokenByGrant.TokenAuthorizationCodeGrant;
internal class AuthorizationCodeValidatedRequest
{
    public required string AuthorizationGrantId { get; init; }
    public required string AuthorizationCodeId { get; init; }
    public string? DPoPJkt { get; init; }
    public required IReadOnlyCollection<string> Scope { get; init; }
    public required IReadOnlyCollection<string> Resource { get; init; }
}