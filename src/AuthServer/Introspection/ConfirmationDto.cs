using System.Text.Json.Serialization;
using AuthServer.Core;

namespace AuthServer.Introspection;
internal class ConfirmationDto
{
    [JsonPropertyName(Parameter.Jkt)]
    public required string Jkt { get; init; }
}
