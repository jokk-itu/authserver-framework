namespace AuthServer.Codes;

internal class EncodedDeviceCode
{
    public required string AuthorizationGrantId { get; init; }
    public required string DeviceCodeId { get; init; }
    public required string UserCodeId { get; init; }
    public required IReadOnlyCollection<string> Scope { get; init; }
    public required string CodeChallenge { get; init; }
    public required string CodeChallengeMethod { get; init; }
    public string? DPoPJkt { get; init; }
}