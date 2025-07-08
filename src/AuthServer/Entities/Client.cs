using AuthServer.Core;
using AuthServer.Enums;

namespace AuthServer.Entities;
public class Client : Entity<string>
{
    public Client(string name, ApplicationType applicationType, TokenEndpointAuthMethod tokenEndpointAuthMethod, int accessTokenExpiration, int dPoPNonceExpiration)
    {
        Id = Guid.NewGuid().ToString();
        Name = string.IsNullOrWhiteSpace(name) ? throw new ArgumentNullException(nameof(name)) : name;
        ApplicationType = applicationType;
        TokenEndpointAuthMethod = tokenEndpointAuthMethod;
        CreatedAt = DateTime.UtcNow;
        RequireConsent = true;
        AccessTokenExpiration = accessTokenExpiration > 0 ? accessTokenExpiration : throw new ArgumentException("must be larger than zero", nameof(accessTokenExpiration));
        DPoPNonceExpiration = dPoPNonceExpiration > 0 ? dPoPNonceExpiration : throw new ArgumentException("must be larger than zero", nameof(dPoPNonceExpiration));
    }

#pragma warning disable CS8618
    // Used to hydrate EF Core model
    private Client() { }
#pragma warning restore

    /// <summary>
    /// Name of client.
    /// </summary>
    public string Name { get; set; }

    /// <summary>
    /// Timestamp at the creation of the client.
    /// </summary>
    public DateTime CreatedAt { get; private init; }

    /// <summary>
    /// Secret of client.
    /// </summary>
    public string? SecretHash { get; private set; }

    /// <summary>
    /// Secret expiration.
    /// </summary>
    public DateTime? SecretExpiresAt { get; private set; }

    /// <summary>
    /// Secret lifetime in seconds.
    /// </summary>
    public int? SecretExpiration { get; set; }

    /// <summary>
    /// Access token lifetime in seconds.
    /// </summary>
    public int AccessTokenExpiration { get; set; }

    /// <summary>
    /// Refresh token lifetime in seconds.
    /// </summary>
    public int? RefreshTokenExpiration { get; set; }

    /// <summary>
    /// Authorization code lifetime in seconds.
    /// </summary>
    public int? AuthorizationCodeExpiration { get; set; }

    /// <summary>
    /// Device code lifetime in seconds.
    /// </summary>
    public int? DeviceCodeExpiration { get; set; }

    /// <summary>
    /// Request uri from a PushedAuthorizationRequest lifetime in seconds.
    /// </summary>
    public int? RequestUriExpiration { get; set; }

    /// <summary>
    /// Lifetime of jwks in seconds.
    /// </summary>
    public int? JwksExpiration { get; set; }

    /// <summary>
    /// DPoPNonce lifetime in seconds.
    /// </summary>
    public int DPoPNonceExpiration { get; set; }

    /// <summary>
    /// Uri to terms of service page.
    /// </summary>
    public string? TosUri { get; set; }

    /// <summary>
    /// Uri to policy page.
    /// </summary>
    public string? PolicyUri { get; set; }

    /// <summary>
    /// Uri to client.
    /// </summary>
    public string? ClientUri { get; set; }

    /// <summary>
    /// Uri to logo of client.
    /// </summary>
    public string? LogoUri { get; set; }

    /// <summary>
    /// Uri which the identity provider can invoke to start authentication flow.
    /// </summary>
    public string? InitiateLoginUri { get; set; }

    /// <summary>
    /// Uri which the identity provider can invoke to log out the client.
    /// </summary>
    public string? BackchannelLogoutUri { get; set; }

    /// <summary>
    /// Uri to fetch a JWK set.
    /// </summary>
    public string? JwksUri { get; set; }

    /// <summary>
    /// JSON array of a JWK set.
    /// </summary>
    public string? Jwks { get; set; }

    /// <summary>
    /// Managed by the authorization server, to determine when to refresh jwks from jwks_uri.
    /// </summary>
    public DateTime? JwksExpiresAt { get; set; }

    /// <summary>
    /// All tokens sent to the client are reference tokens.
    /// </summary>
    public bool RequireReferenceToken { get; set; }

    /// <summary>
    /// All authorization attempts involving an end user requires an active consent grant.
    /// </summary>
    public bool RequireConsent { get; set; }

    /// <summary>
    /// All authorize calls require a request_object parameter,
    /// either directly or by reference.
    /// </summary>
    public bool RequireSignedRequestObject { get; set; }

    /// <summary>
    /// All authorize calls require a request_uri parameter,
    /// from a pushed authorization.
    /// </summary>
    public bool RequirePushedAuthorizationRequests { get; set; }

    /// <summary>
    /// All id tokens must include claims about the end user.
    /// </summary>
    public bool RequireIdTokenClaims { get; set; }
    
    /// <summary>
    /// All access tokens must be DPoP bound.
    /// </summary>
    public bool RequireDPoPBoundAccessTokens { get; set; }

    /// <summary>
    /// Maximum age since last authentication by end user in epoch format
    /// Zero means it always requires authentication by end user.
    /// </summary>
    public int? DefaultMaxAge { get; set; }

    /// <summary>
    /// Type of the client.
    /// </summary>
    public ApplicationType ApplicationType { get; set; }

    /// <summary>
    /// Method of client authentication which is used at the token endpoint.
    /// </summary>
    public TokenEndpointAuthMethod TokenEndpointAuthMethod { get; set; }

    /// <summary>
    /// Type of subject identifier belonging to end users authenticating.
    /// </summary>
    public SubjectType? SubjectType { get; set; }

    /// <summary>
    /// Encoding used to encrypt tokens for client authentication.
    /// </summary>
    public EncryptionEnc? TokenEndpointAuthEncryptionEnc { get; set; }

    /// <summary>
    /// Algorithm used to encrypt tokens for client authentication.
    /// </summary>
    public EncryptionAlg? TokenEndpointAuthEncryptionAlg { get; set; }

    /// <summary>
    /// Algorithm used to sign tokens for client authentication.
    /// </summary>
    public SigningAlg? TokenEndpointAuthSigningAlg { get; set; }

    /// <summary>
    /// Encoding used to encrypt claims for userinfo responses.
    /// </summary>
    public EncryptionEnc? UserinfoEncryptedResponseEnc { get; set; }

    /// <summary>
    /// Algorithm used to encrypt claims for userinfo responses.
    /// </summary>
    public EncryptionAlg? UserinfoEncryptedResponseAlg { get; set; }

    /// <summary>
    /// Algorithm used to sign claims for userinfo responses.
    /// </summary>
    public SigningAlg? UserinfoSignedResponseAlg { get; set; }

    /// <summary>
    /// Encoding used to encrypt request tokens.
    /// </summary>
    public EncryptionEnc? RequestObjectEncryptionEnc { get; set; }

    /// <summary>
    /// Algorithm used to encrypt request tokens.
    /// </summary>
    public EncryptionAlg? RequestObjectEncryptionAlg { get; set; }

    /// <summary>
    /// Algorithm used to sign request tokens.
    /// </summary>
    public SigningAlg? RequestObjectSigningAlg { get; set; }

    /// <summary>
    /// Encoding used to encrypt id tokens.
    /// </summary>
    public EncryptionEnc? IdTokenEncryptedResponseEnc { get; set; }

    /// <summary>
    /// Algorithm used to encrypt id tokens.
    /// </summary>
    public EncryptionAlg? IdTokenEncryptedResponseAlg { get; set; }

    /// <summary>
    /// Algorithm used to sign id tokens.
    /// </summary>
    public SigningAlg? IdTokenSignedResponseAlg { get; set; }

    public SectorIdentifier? SectorIdentifier { get; set; }
    public ICollection<RedirectUri> RedirectUris { get; set; } = [];
    public ICollection<PostLogoutRedirectUri> PostLogoutRedirectUris { get; set; } = [];
    public ICollection<RequestUri> RequestUris { get; set; } = [];
    public ICollection<GrantType> GrantTypes { get; set; } = [];
    public ICollection<Scope> Scopes { get; set; } = [];
    public ICollection<Contact> Contacts { get; set; } = [];
    public ICollection<ResponseType> ResponseTypes { get; set; } = [];
    public ICollection<Consent> Consents { get; set; } = [];
    public ICollection<AuthorizationGrant> AuthorizationGrants { get; set; } = [];
    public ICollection<ClientToken> ClientTokens { get; set; } = [];
    public ICollection<AuthorizeMessage> AuthorizeMessages { get; set; } = [];
    public ICollection<ClientAuthenticationContextReference> ClientAuthenticationContextReferences { get; set; } = [];
    public ICollection<DPoPNonce> Nonces { get; set; } = [];

    public void SetSecret(string secretHash)
    {
        SecretHash = secretHash;
        if (SecretExpiration is not null)
        {
            SecretExpiresAt = DateTime.UtcNow.AddSeconds(SecretExpiration.Value);
        }
        else
        {
            SecretExpiresAt = null;
        }
    }
}