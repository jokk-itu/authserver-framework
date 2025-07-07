namespace AuthServer.GrantManagement.Query;
internal class GrantResponse
{
    public IReadOnlyCollection<ScopeDto> Scopes { get; set; } = [];
    public IReadOnlyCollection<string> Claims { get; set; } = [];
    public long CreatedAt { get; set; }
    public long UpdatedAt { get; set; }
}