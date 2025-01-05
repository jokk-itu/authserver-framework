namespace AuthServer.RequestAccessors.GrantManagement;

internal class GrantManagementRequest
{
    public required HttpMethod Method { get; init; }
    public required string AccessToken { get; init; }
    public string? GrantId { get; init; }
}