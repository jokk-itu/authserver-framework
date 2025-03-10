﻿using AuthServer.Authentication.Models;

namespace AuthServer.RequestAccessors.Revocation;

internal record RevocationRequest
{
    public string? Token { get; init; }
    public string? TokenTypeHint { get; init; }
    public IReadOnlyCollection<ClientAuthentication> ClientAuthentications { get; init; } = [];
}