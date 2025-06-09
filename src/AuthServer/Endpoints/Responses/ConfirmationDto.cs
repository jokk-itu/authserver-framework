using System.Text.Json.Serialization;
using AuthServer.Core;

namespace AuthServer.Endpoints.Responses;
internal class ConfirmationDto
{
    [JsonPropertyName(Parameter.Jkt)]
    public required string Jkt { get; init; }
}
