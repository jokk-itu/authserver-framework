using System.Text.Json.Serialization;
using AuthServer.Core;

namespace AuthServer.Introspection;
internal class PostIntrospectionResponse
{
    [JsonPropertyName(Parameter.Active)]
    public required bool Active { get; init; }

    [JsonPropertyName(Parameter.Scope)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Scope { get; init; }

    [JsonPropertyName(Parameter.ClientId)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ClientId { get; init; }

    [JsonPropertyName(Parameter.Username)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Username { get; init; }

    [JsonPropertyName(Parameter.TokenType)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TokenType { get; init; }

    [JsonPropertyName(Parameter.Expires)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? ExpiresAt { get; init; }

    [JsonPropertyName(Parameter.IssuedAt)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? IssuedAt { get; init; }

    [JsonPropertyName(Parameter.NotBefore)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? NotBefore { get; init; }

    [JsonPropertyName(Parameter.Subject)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Subject { get; init; }

    [JsonPropertyName(Parameter.Audience)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IEnumerable<string>? Audience { get; init; }

    [JsonPropertyName(Parameter.Issuer)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Issuer { get; init; }

    [JsonPropertyName(Parameter.JwtId)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? JwtId { get; init; }

    [JsonPropertyName(Parameter.AuthTime)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public long? AuthTime { get; init; }

    [JsonPropertyName(Parameter.Acr)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Acr { get; init; }

    [JsonPropertyName(Parameter.Cnf)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ConfirmationDto? Cnf { get; init; }

    [JsonPropertyName(Parameter.AccessControl)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IDictionary<string, object>? AccessControl { get; init; }
}