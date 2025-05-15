namespace AuthServer.Options;

public class DiscoveryDocument
{
    public string Issuer { get; set; } = null!;
    public string? ServiceDocumentation { get; set; }
    public string? OpPolicyUri { get; set; }
    public string? OpTosUri { get; set; }

    public ICollection<string> ProtectedResources { get; set; } = [];
    public ICollection<string> ClaimsSupported { get; set; } = [];
    public ICollection<string> AcrValuesSupported { get; set; } = [];
    public ICollection<string> ScopesSupported { get; set; } = [];

    public ICollection<string> IdTokenSigningAlgValuesSupported { get; set; } = [];
    public ICollection<string> IdTokenEncryptionAlgValuesSupported { get; set; } = [];
    public ICollection<string> IdTokenEncryptionEncValuesSupported { get; set; } = [];

    public ICollection<string> UserinfoSigningAlgValuesSupported { get; set; } = [];
    public ICollection<string> UserinfoEncryptionAlgValuesSupported { get; set; } = [];
    public ICollection<string> UserinfoEncryptionEncValuesSupported { get; set; } = [];

    public ICollection<string> RequestObjectSigningAlgValuesSupported { get; set; } = [];
    public ICollection<string> RequestObjectEncryptionAlgValuesSupported { get; set; } = [];
    public ICollection<string> RequestObjectEncryptionEncValuesSupported { get; set; } = [];

    public ICollection<string> TokenEndpointAuthSigningAlgValuesSupported { get; set; } = [];
    public ICollection<string> TokenEndpointAuthEncryptionAlgValuesSupported { get; set; } = [];
    public ICollection<string> TokenEndpointAuthEncryptionEncValuesSupported { get; set; } = [];

    public ICollection<string> IntrospectionEndpointAuthSigningAlgValuesSupported { get; set; } = [];
    public ICollection<string> RevocationEndpointAuthSigningAlgValuesSupported { get; set; } = [];
    public ICollection<string> DPoPSigningAlgValuesSupported { get; set; } = [];

    public bool RequireSignedRequestObject { get; set; }
    public bool RequirePushedAuthorizationRequests { get; set; }
    public bool GrantManagementActionRequired { get; set; }
}