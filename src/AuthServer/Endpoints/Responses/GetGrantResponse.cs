using System.Text.Json.Serialization;
using AuthServer.Core;

namespace AuthServer.Endpoints.Responses;
internal class GetGrantResponse
{
    [JsonPropertyName(Parameter.Scopes)]
    public IEnumerable<GetGrantScopeDto> Scopes { get; set; } = [];

    [JsonPropertyName(Parameter.Claims)]
    public IEnumerable<string> Claims { get; set; } = [];

    [JsonPropertyName(Parameter.CreatedAt)]
    public DateTime CreatedAt { get; set; }

    [JsonPropertyName(Parameter.UpdatedAt)]
    public DateTime UpdatedAt { get; set; }
}
