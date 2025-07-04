﻿using AuthServer.Enums;

namespace AuthServer.Entities;
public abstract class ClientToken : Token
{
    protected ClientToken(Client client, TokenType tokenType, string audience, string issuer, string? scope, int? expiresAt, string? jkt)
        : base(tokenType, audience, issuer, scope, expiresAt, jkt)
    {
        Client = client ?? throw new ArgumentNullException(nameof(client));
    }

#pragma warning disable CS8618
    // Used to hydrate EF Core model
    protected ClientToken() { }
#pragma warning restore

    public Client Client { get; private init; }
}
