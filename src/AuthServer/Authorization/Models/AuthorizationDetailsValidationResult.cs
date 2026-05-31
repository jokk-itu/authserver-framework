namespace AuthServer.Authorization.Models;

internal class AuthorizationDetailsValidationResult
{
    public IReadOnlyCollection<string> AuthorizationDetails { get; init; } = [];

    public AuthorizationDetailsError? Error { get; init; }

    public bool IsValid => Error is null;
}