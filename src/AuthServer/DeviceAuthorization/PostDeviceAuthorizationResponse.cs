using System.Text.Json.Serialization;
using AuthServer.Core;

namespace AuthServer.DeviceAuthorization;

public class PostDeviceAuthorizationResponse
{
    [JsonPropertyName(Parameter.DeviceCode)]
    public required string DeviceCode { get; init; }
    
    [JsonPropertyName(Parameter.UserCode)]
    public required string UserCode { get; init; }
    
    [JsonPropertyName(Parameter.VerificationUri)]
    public required string VerificationUri { get; init; }
    
    [JsonPropertyName(Parameter.VerificationUriComplete)]
    public required string VerificationUriComplete { get; init; }
    
    [JsonPropertyName(Parameter.ExpiresIn)]
    public required int ExpiresIn { get; init; }
    
    [JsonPropertyName(Parameter.Interval)]
    public required int Interval { get; init; }
}