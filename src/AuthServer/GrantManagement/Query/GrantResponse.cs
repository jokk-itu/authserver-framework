namespace AuthServer.GrantManagement.Query;
internal class GrantResponse
{
    public IReadOnlyCollection<ScopeDto> Scopes { get; set; } = [];
    public IReadOnlyCollection<string> Claims { get; set; } = [];
    public DateTime CreatedAt { get; set; }
}
