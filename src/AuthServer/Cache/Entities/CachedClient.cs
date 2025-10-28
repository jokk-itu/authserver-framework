using AuthServer.Enums;

namespace AuthServer.Cache.Entities;
internal class CachedClient
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required string? SecretHash { get; init; }
    public required DateTime? SecretExpiresAt { get; init; }
    public required int AccessTokenExpiration { get; init; }
    public required int? DeviceCodeExpiration { get; init; }
    public required string? ClientUri { get; init; }
    public required string? LogoUri { get; init; }
    public required bool RequireConsent { get; init; }
    public required bool RequireSignedRequestObject { get; init; }
    public required bool RequirePushedAuthorizationRequests { get; init; }
    public required bool RequireDPoPBoundAccessTokens { get; init; }
    public required TokenEndpointAuthMethod TokenEndpointAuthMethod { get; init; }

    public required EncryptionEnc? TokenEndpointAuthEncryptionEnc { get; init; }
    public required SigningAlg? TokenEndpointAuthSigningAlg { get; set; }

    public required EncryptionEnc? RequestObjectEncryptionEnc { get; set; }
    public required SigningAlg? RequestObjectSigningAlg { get; set; }

    public required IReadOnlyCollection<string> Scopes { get; init; }
    public required IReadOnlyCollection<string> GrantTypes { get; init; }
    public required IReadOnlyCollection<string> ResponseTypes { get; init; }
    public required IReadOnlyCollection<string> PostLogoutRedirectUris { get; init; }
    public required IReadOnlyCollection<string> RedirectUris { get; init; }
    public required IReadOnlyCollection<string> RequestUris { get; init; }
}