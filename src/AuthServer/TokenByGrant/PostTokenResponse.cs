using System.Text.Json.Serialization;
using AuthServer.Core;

namespace AuthServer.TokenByGrant;

internal class PostTokenResponse
{
    [JsonPropertyName(Parameter.AccessToken)]
    public required string AccessToken { get; init; }

    [JsonPropertyName(Parameter.RefreshToken)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RefreshToken { get; init; }

    [JsonPropertyName(Parameter.IdToken)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IdToken { get; init; }

    [JsonPropertyName(Parameter.TokenType)]
    public required string TokenType { get; init; }

    [JsonPropertyName(Parameter.ExpiresIn)]
    public required long ExpiresIn { get; init; }

    [JsonPropertyName(Parameter.Scope)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Scope { get; init; }
    
    [JsonPropertyName(Parameter.GrantId)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? GrantId { get; init; }
    
    [JsonPropertyName(Parameter.IssuedTokenType)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IssuedTokenType { get; init; }
}