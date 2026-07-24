namespace AuthServer.Repositories.Models;

internal class ConsentDto
{
    public required string SubjectIdentifier { get; init; }
    public required string ClientId { get; init; }
    public required IReadOnlyCollection<string> ConsentedScopes { get; init; }
    public required IReadOnlyCollection<string> ConsentedClaims { get; init; }
    public required IReadOnlyCollection<string> ConsentedAuthorizationDetailTypes { get; init; }
}