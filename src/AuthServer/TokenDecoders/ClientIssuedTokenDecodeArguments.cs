namespace AuthServer.TokenDecoders;
internal class ClientIssuedTokenDecodeArguments
{
    public required bool ValidateLifetime { get; init; }
    public required string ClientId { get; init; }
    public string? SubjectId { get; init; }
    public required string TokenType { get; init; }
    public bool UseJwkHeaderSignatureValidation { get; init; }
    public required IReadOnlyCollection<string> Algorithms { get; init; }
    public required ClientTokenAudience Audience { get; init; }
}