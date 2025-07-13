namespace AuthServer.TokenByGrant.TokenDeviceCodeGrant;
internal class DeviceCodeValidatedRequest
{
    public required string ClientId { get; init; }
    public required string AuthorizationGrantId { get; init; }
    public required string DeviceCodeId { get; init; }
    public string? DPoPJkt { get; init; }
    public required IReadOnlyCollection<string> Scope { get; init; }
    public required IReadOnlyCollection<string> Resource { get; init; }
}