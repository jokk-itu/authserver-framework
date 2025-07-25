namespace AuthServer.Codes;

internal class EncodedDeviceCode
{
    public string? AuthorizationGrantId { get; init; }
    public string? GrantManagementAction { get; init; }
    public required string DeviceCodeId { get; init; }
    public required string UserCodeId { get; init; }
    public required IReadOnlyCollection<string> Scope { get; init; }
    public required IReadOnlyCollection<string> Resource { get; init; }
    public IReadOnlyCollection<string> AcrValues { get; init; } = [];
    public required string CodeChallenge { get; init; }
    public required string CodeChallengeMethod { get; init; }
    public string? DPoPJkt { get; init; }
}