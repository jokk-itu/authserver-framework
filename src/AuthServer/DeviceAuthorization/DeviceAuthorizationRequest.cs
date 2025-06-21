using AuthServer.Authentication.Models;

namespace AuthServer.DeviceAuthorization;

internal class DeviceAuthorizationRequest
{
    public string? CodeChallenge { get; init; }
    public string? CodeChallengeMethod { get; init; }
    public string? Nonce { get; init; }
    public string? MaxAge { get; init; }
    public string? RequestObject { get; init; }
    public string? RequestUri { get ; init; }
    public string? GrantId { get; init; }
    public string? GrantManagementAction { get; init; }
    public string? DPoP { get; init; }
    public IReadOnlyCollection<string> Scope { get; init; } = [];
    public IReadOnlyCollection<string> AcrValues { get; init; } = [];
    public IReadOnlyCollection<string> Resource { get; init; } = [];
    public IReadOnlyCollection<ClientAuthentication> ClientAuthentications { get; init; } = [];
}