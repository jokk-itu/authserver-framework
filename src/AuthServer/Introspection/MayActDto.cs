using System.Text.Json.Serialization;
using AuthServer.Core;

namespace AuthServer.Introspection;
internal class MayActDto
{
    [JsonPropertyName(Parameter.Subject)]
    public required string Sub { get; init; }
}
