using System.Text.Json.Serialization;

namespace AuthServer.Endpoints.Responses;

internal class GetDiscoveryResponse
{
    [JsonPropertyName("issuer")]
    public required string Issuer { get; init; }

    [JsonPropertyName("service_documentation")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? ServiceDocumentation { get; init; }

    [JsonPropertyName("op_policy_uri")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? OpPolicyUri { get; init; }

    [JsonPropertyName("op_tos_uri")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? OpTosUri { get; init; }

    [JsonPropertyName("authorization_endpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? AuthorizationEndpoint { get; init; }

    [JsonPropertyName("token_endpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? TokenEndpoint { get; init; }

    [JsonPropertyName("userinfo_endpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? UserinfoEndpoint { get; init; }

    [JsonPropertyName("jwks_uri")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? JwksUri { get; init; }

    [JsonPropertyName("registration_endpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RegistrationEndpoint { get; init; }

    [JsonPropertyName("end_session_endpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? EndSessionEndpoint { get; init; }

    [JsonPropertyName("introspection_endpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? IntrospectionEndpoint { get; init; }

    [JsonPropertyName("revocation_endpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? RevocationEndpoint { get; init; }

    [JsonPropertyName("pushed_authorization_request_endpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? PushedAuthorizationRequestEndpoint { get; init; }

    [JsonPropertyName("grant_management_endpoint")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? GrantManagementEndpoint { get; init; }

    [JsonPropertyName("protected_resources")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? ProtectedResources { get; init; }

    [JsonPropertyName("claims_support")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? ClaimsSupported { get; init; }

    [JsonPropertyName("claim_types_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? ClaimTypesSupported { get; init; }

    [JsonPropertyName("prompt_values_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? PromptValuesSupported { get; init; }

    [JsonPropertyName("display_values_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? DisplayValuesSupported { get; init; }

    [JsonPropertyName("subject_types_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? SubjectTypesSupported { get; init; }

    [JsonPropertyName("grant_types_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? GrantTypesSupported { get; init; }

    [JsonPropertyName("acr_values_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? AcrValuesSupported { get; init; }

    [JsonPropertyName("challenge_methods_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? ChallengeMethodsSupported { get; init; }

    [JsonPropertyName("scopes_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? ScopesSupported { get; init; }

    [JsonPropertyName("response_types_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? ResponseTypesSupported { get; init; }

    [JsonPropertyName("response_modes_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? ResponseModesSupported { get; init; }

    [JsonPropertyName("introspection_endpoint_auth_methods_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? IntrospectionEndpointAuthMethodsSupported { get; init; }

    [JsonPropertyName("revocation_endpoint_auth_methods_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? RevocationEndpointAuthMethodsSupported { get; init; }

    [JsonPropertyName("token_endpoint_auth_methods_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? TokenEndpointAuthMethodsSupported { get; init; }

    [JsonPropertyName("id_token_signing_alg_values_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? IdTokenSigningAlgValuesSupported { get; init; }

    [JsonPropertyName("id_token_encryption_alg_values_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? IdTokenEncryptionAlgValuesSupported { get; init; }

    [JsonPropertyName("id_token_encryption_enc_values_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? IdTokenEncryptionEncValuesSupported { get; set; }

    [JsonPropertyName("userinfo_signing_alg_values_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? UserinfoSigningAlgValuesSupported { get; init; }

    [JsonPropertyName("userinfo_encryption_alg_values_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? UserinfoEncryptionAlgValuesSupported { get; init; }

    [JsonPropertyName("userinfo_encryption_enc_values_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? UserinfoEncryptionEncValuesSupported { get; init; }

    [JsonPropertyName("request_object_signing_alg_values_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? RequestObjectSigningAlgValuesSupported { get; init; }

    [JsonPropertyName("request_object_encryption_alg_values_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? RequestObjectEncryptionAlgValuesSupported { get; init; }

    [JsonPropertyName("request_object_encryption_enc_values_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? RequestObjectEncryptionEncValuesSupported { get; init; }

    [JsonPropertyName("token_endpoint_auth_signing_alg_values_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? TokenEndpointAuthSigningAlgValuesSupported { get; init; }

    [JsonPropertyName("token_endpoint_auth_encryption_alg_values_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? TokenEndpointAuthEncryptionAlgValuesSupported { get; init; }

    [JsonPropertyName("token_endpoint_auth_encryption_enc_values_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? TokenEndpointAuthEncryptionEncValuesSupported { get; init; }

    [JsonPropertyName("introspection_endpoint_auth_signing_alg_values_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? IntrospectionEndpointAuthSigningAlgValuesSupported { get; init; }

    [JsonPropertyName("revocation_endpoint_auth_signing_alg_values_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? RevocationEndpointAuthSigningAlgValuesSupported { get; init; }
    
    [JsonPropertyName("dpop_signing_alg_values_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? DPoPSigningAlgValuesSupported { get; init; }

    [JsonPropertyName("authorization_response_iss_parameter_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? AuthorizationResponseIssParameterSupported { get; init; }

    [JsonPropertyName("backchannel_logout_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? BackchannelLogoutSupported { get; init; }

    [JsonPropertyName("require_request_uri_registration")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? RequireRequestUriRegistration { get; init; }

    [JsonPropertyName("claims_parameter_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? ClaimsParameterSupported { get; init; }

    [JsonPropertyName("request_parameter_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? RequestParameterSupported { get; init; }

    [JsonPropertyName("request_uri_parameter_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? RequestUriParameterSupported { get; init; }

    [JsonPropertyName("require_signed_request_object")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? RequireSignedRequestObject { get; init; }

    [JsonPropertyName("require_pushed_authorization_requests")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? RequirePushedAuthorizationRequests { get; init; }

    [JsonPropertyName("grant_management_action_required")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? GrantManagementActionRequired { get; init; }

    [JsonPropertyName("grant_management_actions_supported")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public ICollection<string>? GrantManagementActionsSupported { get; init; }
}