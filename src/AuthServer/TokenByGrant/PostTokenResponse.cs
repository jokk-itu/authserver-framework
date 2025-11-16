using System.Text.Json.Serialization;
using AuthServer.Core;

namespace AuthServer.TokenByGrant;

internal class PostTokenResponse
{
    [JsonPropertyName(Parameter.AccessToken)]
    public required string AccessToken { get; init; }

    [JsonPropertyName(Parameter.RefreshToken)]
    public string? RefreshToken { get; init; }

    [JsonPropertyName(Parameter.IdToken)]
    public string? IdToken { get; init; }

    [JsonPropertyName(Parameter.TokenType)]
    public required string TokenType { get; init; }

    [JsonPropertyName(Parameter.ExpiresIn)]
    public required long ExpiresIn { get; init; }

    [JsonPropertyName(Parameter.Scope)]
    public string? Scope { get; init; }
    
    [JsonPropertyName(Parameter.GrantId)]
    public string? GrantId { get; init; }
    
    [JsonPropertyName(Parameter.IssuedTokenType)]
    public string? IssuedTokenType { get; init; }
}