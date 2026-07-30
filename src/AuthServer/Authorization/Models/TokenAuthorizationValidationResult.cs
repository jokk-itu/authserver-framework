namespace AuthServer.Authorization.Models;

internal class TokenAuthorizationValidationResult
{
    public IReadOnlyCollection<string> Scopes { get; init; } = [];

    public IReadOnlyCollection<string> Resources { get; init; } = [];

    public TokenAuthorizationValidationError? Error { get; init; }

    public bool IsValid => Error is null;
};