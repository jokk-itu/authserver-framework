using AuthServer.Authentication.Models;

namespace AuthServer.TokenByGrant;

internal class TokenRequest
{
    public string? GrantType { get; init; }
    public string? DeviceCode { get; init; }
    public string? Code { get; init; }
    public string? CodeVerifier { get; init; }
    public string? RedirectUri { get; init; }
    public string? RefreshToken { get; init; }
    public string? DPoP { get; init; }
    public IReadOnlyCollection<string> Scope { get; init; } = [];
    public IReadOnlyCollection<string> Resource { get; init; } = [];
    public IReadOnlyCollection<ClientAuthentication> ClientAuthentications { get; init; } = [];
}