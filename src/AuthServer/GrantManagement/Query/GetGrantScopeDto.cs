using System.Text.Json.Serialization;
using AuthServer.Core;

namespace AuthServer.GrantManagement.Query;
internal class GetGrantScopeDto
{
    [JsonPropertyName(Parameter.Scope)]
    public IEnumerable<string> Scopes { get; set; } = [];

    [JsonPropertyName(Parameter.Resource)]
    public IEnumerable<string> Resources { get; set; } = [];
}