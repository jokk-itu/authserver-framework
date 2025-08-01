﻿using System.Linq.Expressions;
using AuthServer.Core;

namespace AuthServer.Entities;
public abstract class AuthorizationGrant : Entity<string>
{
    protected AuthorizationGrant(Session session, Client client, string subject, AuthenticationContextReference authenticationContextReference)
    {
        Id = Guid.NewGuid().ToString();
        CreatedAuthTime = DateTime.UtcNow;
        UpdatedAuthTime = DateTime.UtcNow;
        Session = session ?? throw new ArgumentNullException(nameof(session));
        Client = client ?? throw new ArgumentNullException(nameof(client));
        Subject = subject ?? throw new ArgumentNullException(nameof(subject));
        AuthenticationContextReference = authenticationContextReference ?? throw new ArgumentNullException(nameof(authenticationContextReference));
    }

#pragma warning disable CS8618
    // Used to hydrate EF Core model
    protected AuthorizationGrant(){}
#pragma warning restore

    public DateTime UpdatedAuthTime { get; private set; }
    public DateTime CreatedAuthTime { get; private init; }
    public DateTime? RevokedAt { get; private set; }
    public string Subject { get; private init; }
    public Session Session { get; private init; }
    public Client Client { get; private init; }
    public AuthenticationContextReference AuthenticationContextReference { get; set; }
    public ICollection<AuthorizationGrantNonce> Nonces { get; init; } = [];
    public ICollection<GrantToken> GrantTokens { get; init; } = [];
    public ICollection<AuthenticationMethodReference> AuthenticationMethodReferences { get; init; } = [];
    public ICollection<AuthorizationGrantConsent> AuthorizationGrantConsents { get; init; } = [];

    public void Revoke()
    {
        RevokedAt ??= DateTime.UtcNow;
    }

    public void UpdateAuthTime()
    {
        UpdatedAuthTime = DateTime.UtcNow;
    }

    public static readonly Expression<Func<AuthorizationGrant, bool>> IsActive = a => a.RevokedAt == null;
    public static readonly Expression<Func<AuthorizationGrant, bool>> IsExpired = a => a.RevokedAt != null;
}