namespace AuthServer.RequestAccessors.GrantManagement;

internal class GrantManagementRequest
{
    public required string AccessToken { get; init; }
    public string? GrantId { get; init; }
}