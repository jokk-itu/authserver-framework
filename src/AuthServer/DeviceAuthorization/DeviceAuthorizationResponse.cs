namespace AuthServer.DeviceAuthorization;

internal class DeviceAuthorizationResponse
{
    public required string DeviceCode { get; init; }
    public required string UserCode { get; init; }
    public required string VerificationUri { get; init; }
    public required string VerificationUriComplete { get; init; }
    public required int ExpiresIn { get; init; }
    public required int Interval { get; init; }
}