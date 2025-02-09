namespace AuthServer.GrantManagement.Query;
internal class ScopeDto
{
    public IReadOnlyCollection<string> Scopes { get; set; } = [];
    public IReadOnlyCollection<string> Resources { get; set; } = [];
}
