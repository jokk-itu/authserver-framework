namespace AuthServer.Authorization.Models;
internal class DPoPValidationResult
{
    public bool IsValid { get; init; }
    public bool RenewDPoPNonce { get; init; }
    public string? DPoPJkt { get; init; }
    public string? AccessTokenHash { get; init; }
}