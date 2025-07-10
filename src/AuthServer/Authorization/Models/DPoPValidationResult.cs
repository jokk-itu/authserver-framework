namespace AuthServer.Authorization.Models;
internal class DPoPValidationResult
{
    public required bool IsValid { get; init; }
    public bool RenewDPoPNonce { get; init; }
    public string? DPoPJkt { get; init; }
    public string? DPoPNonce { get; init; }
    public string? AccessTokenHash { get; init; }
}