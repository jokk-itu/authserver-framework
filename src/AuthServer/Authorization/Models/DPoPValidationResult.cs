namespace AuthServer.Authorization.Models;
internal class DPoPValidationResult
{
    public required bool IsValid { get; init; }
    public string? DPoPJkt { get; init; }
    public string? DPoPNonce { get; init; }
}
