namespace AuthServer.RequestAccessors.EndSession;

internal class EndSessionRequest
{
    public string? IdTokenHint { get; init; }
    public string? ClientId { get; init; }
    public string? PostLogoutRedirectUri { get; init; }
    public string? State { get; init; }
}