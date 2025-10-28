namespace AuthServer.TokenByGrant.TokenExchangeGrant.Abstractions;
public class ValidatedTokenExchangeRequest
{
    /// <summary>
    /// 
    /// </summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// 
    /// </summary>
    public required string RequestedTokenType { get; init; }

    /// <summary>
    /// 
    /// </summary>
    public required string SubjectToken { get; init; }

    /// <summary>
    /// 
    /// </summary>
    public required string SubjectTokenType { get; init; }

    /// <summary>
    /// 
    /// </summary>
    public string? ActorToken { get; init; }

    /// <summary>
    /// 
    /// </summary>
    public string? ActorTokenType { get; init; }

    /// <summary>
    /// 
    /// </summary>
    public IReadOnlyCollection<string> Scope { get; init; } = [];

    /// <summary>
    /// 
    /// </summary>
    public IReadOnlyCollection<string> Resource { get; init; } = [];
}