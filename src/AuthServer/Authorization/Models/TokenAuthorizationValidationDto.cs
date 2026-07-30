namespace AuthServer.Authorization.Models;

internal abstract class TokenAuthorizationValidationDto
{
    public required IReadOnlyCollection<string> Scopes { get; init; }
    public required IReadOnlyCollection<string> Resources { get; init; }
    public required IReadOnlyCollection<string> AuthorizationDetails { get; init; }
}