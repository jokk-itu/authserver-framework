using System.Text.Json.Serialization;

namespace AuthServer.Jwks;
internal class GetJwksResponse
{
    [JsonPropertyName("keys")]
    public required IEnumerable<JwkDto> Keys { get; init; }
}
