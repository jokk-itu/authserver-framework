﻿using AuthServer.Core;

namespace AuthServer.Entities;

public class SubjectIdentifier : Entity<string>
{
    public SubjectIdentifier()
    {
        Id = Guid.NewGuid().ToString();
    }

    public ICollection<Session> Sessions { get; private init; } = [];
    public ICollection<Consent> Consents { get; private init; } = [];
}