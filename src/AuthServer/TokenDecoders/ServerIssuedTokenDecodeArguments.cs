﻿namespace AuthServer.TokenDecoders;
internal class ServerIssuedTokenDecodeArguments
{
    public required bool ValidateLifetime { get; init; }
    public required IReadOnlyCollection<string> Audiences { get; init; }
    public required IReadOnlyCollection<string> TokenTypes { get; init; }
}