namespace AuthServer.Authorization.Models;

internal class ScopeResourceValidationResult
{
    public IReadOnlyCollection<string> Scopes { get; init; } = [];

    public IReadOnlyCollection<string> Resources { get; init; } = [];

    public ScopeResourceError? Error { get; init; }

    public bool IsValid => Error is null;
};