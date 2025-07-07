using System.Text.Json.Serialization;
using AuthServer.Core;

namespace AuthServer.GrantManagement.Query;
internal class GetGrantResponse
{
    [JsonPropertyName(Parameter.Scopes)]
    public IEnumerable<GetGrantScopeDto> Scopes { get; set; } = [];

    [JsonPropertyName(Parameter.Claims)]
    public IEnumerable<string> Claims { get; set; } = [];

    [JsonPropertyName(Parameter.CreatedAt)]
    public long CreatedAt { get; set; }

    [JsonPropertyName(Parameter.UpdatedAt)]
    public long UpdatedAt { get; set; }
}