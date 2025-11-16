using AuthServer.TokenDecoders;

namespace AuthServer.TokenByGrant.TokenExchangeGrant;
internal class TokenExchangeValidatedRequest
{
    public required string RequestedTokenType { get; init; }
    public required TokenResult SubjectToken { get; init; }
    public TokenResult? ActorToken { get; init; }
    public string? Jkt { get; init; }
    public required IReadOnlyCollection<string> Scope { get; init; }
    public required IReadOnlyCollection<string> Resource { get; init; }
}