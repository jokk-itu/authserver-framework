using System.Text.Json.Serialization;

namespace AuthServer.Authorization.Models;

public abstract class AuthorizationDetailDto
{
    /// <summary>
    /// The type field. It is required.
    /// <remarks>https://datatracker.ietf.org/doc/html/rfc9396#name-authorization-details-types</remarks>
    /// </summary>
    [JsonPropertyName("type")]
    public required string Type { get; init; }

    /// <summary>
    /// The locations field. It is optional.
    /// <remarks>https://datatracker.ietf.org/doc/html/rfc9396#name-common-data-fields</remarks>
    /// </summary>
    [JsonPropertyName("locations")]
    public IReadOnlyCollection<string> Locations { get; set; } = [];
}