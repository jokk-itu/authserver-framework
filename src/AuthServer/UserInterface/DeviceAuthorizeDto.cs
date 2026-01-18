namespace AuthServer.UserInterface;

public class DeviceAuthorizeDto
{
    public required string ClientId { get; init; }
    public string? AuthorizationGrantId { get; init; }
    public string? GrantManagementAction { get; init; }
    public required string DeviceCodeId { get; init; }
    public required string UserCodeId { get; init; }
    public required IReadOnlyCollection<string> Scope { get; init; }
    public IReadOnlyCollection<string> AcrValues { get; init; } = [];
}