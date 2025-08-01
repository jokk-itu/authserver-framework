﻿namespace AuthServer.Core;
public static class Parameter
{
    public const string ResponseType = "response_type";
    public const string ResponseMode = "response_mode";
    public const string ClientId = "client_id";
    public const string ClientSecret = "client_secret";
    public const string RedirectUri = "redirect_uri";
    public const string Scope = "scope";
    public const string State = "state";
    public const string Display = "display";
    public const string Request = "request";
    public const string RequestUri = "request_uri";
    public const string CodeChallenge = "code_challenge";
    public const string CodeChallengeMethod = "code_challenge_method";
    public const string CodeVerifier = "code_verifier";
    public const string Nonce = "nonce";
    public const string Code = "code";
    public const string RefreshToken = "refresh_token";
    public const string AccessToken = "access_token";
    public const string IdToken = "id_token";
    public const string LogoutToken = "logout_token";
    public const string TokenType = "token_type";
    public const string ExpiresIn = "expires_in";
    public const string GrantType = "grant_type";
    public const string RedirectUris = "redirect_uris";
    public const string ResponseTypes = "response_types";
    public const string GrantTypes = "grant_types";
    public const string ApplicationType = "application_type";
    public const string Contacts = "contacts";
    public const string ClientName = "client_name";
    public const string PolicyUri = "policy_uri";
    public const string TosUri = "tos_uri";
    public const string SubjectType = "subject_type";
    public const string TokenEndpointAuthMethod = "token_endpoint_auth_method";
    public const string ClientSecretExpiresAt = "client_secret_expires_at";
    public const string ClientIdIssuedAt = "client_id_issued_at";
    public const string RegistrationAccessToken = "registration_access_token";
    public const string RegistrationClientUri = "registration_client_uri";
    public const string Error = "error";
    public const string ErrorDescription = "error_description";
    public const string Prompt = "prompt";
    public const string MaxAge = "max_age";
    public const string IdTokenHint = "id_token_hint";
    public const string LoginHint = "login_hint";
    public const string AcrValues = "acr_values";
    public const string Resource = "resource";
    public const string Issuer = "iss";
    public const string DefaultMaxAge = "default_max_age";
    public const string InitiateLoginUri = "initiate_login_uri";
    public const string LogoUri = "logo_uri";
    public const string ClientUri = "client_uri";
    public const string PostLogoutRedirectUri = "post_logout_redirect_uri";
    public const string PostLogoutRedirectUris = "post_logout_redirect_uris";
    public const string BackchannelLogoutUri = "backchannel_logout_uri";
    public const string SectorIdentifierUri = "sector_identifier_uri";
    public const string Token = "token";
    public const string TokenTypeHint = "token_type_hint";
    public const string Active = "active";
    public const string IssuedAt = "iat";
    public const string Expires = "exp";
    public const string JwtId = "jti";
    public const string NotBefore = "nbf";
    public const string Subject = "sub";
    public const string Username = "username";
    public const string Audience = "aud";
    public const string Jwks = "jwks";
    public const string JwksUri = "jwks_uri";
    public const string TokenEndpointAuthSigningAlg = "token_endpoint_auth_signing_alg";
    public const string TokenEndpointAuthEncryptionAlg = "token_endpoint_auth_encryption_alg";
    public const string TokenEndpointAuthEncryptionEnc = "token_endpoint_auth_encryption_enc";
    public const string DefaultAcrValues = "default_acr_values";
    public const string RequestUris = "request_uris";
    public const string RequirePushedAuthorizationRequests = "require_pushed_authorization_requests";
    public const string RequireSignedRequestObject = "require_signed_request_object";
    public const string RequireIdTokenClaims = "require_id_token_claims";
    public const string RequestObjectEncryptionEnc = "request_object_encryption_enc";
    public const string RequestObjectEncryptionAlg = "request_object_encryption_alg";
    public const string RequestObjectSigningAlg = "request_object_signing_alg";
    public const string UserinfoEncryptedResponseEnc = "userinfo_encrypted_response_enc";
    public const string UserinfoEncryptedResponseAlg = "userinfo_encrypted_response_alg";
    public const string UserinfoSignedResponseAlg = "userinfo_signed_response_alg";
    public const string IdTokenEncryptedResponseEnc = "id_token_encrypted_response_enc";
    public const string IdTokenEncryptedResponseAlg = "id_token_encrypted_response_alg";
    public const string IdTokenSignedResponseAlg = "id_token_signed_response_alg";
    public const string ClientAssertionType = "client_assertion_type";
    public const string ClientAssertion = "client_assertion";
    public const string DPoP = "dpop";
    public const string DPoPNonce = "DPoP-Nonce";
    public const string DPoPJkt = "dpop_jkt";
    public const string DPoPBoundAccessTokens = "dpop_bound_access_tokens";
    public const string DPoPNonceExpiration = "dpop_nonce_expiration";
    public const string GrantId = "grant_id";
    public const string GrantManagementAction = "grant_management_action";
    public const string Scopes = "scopes";
    public const string Claims = "claims";
    public const string AuthTime = "auth_time";
    public const string Acr = "acr";
    public const string AccessControl = "access_control";
    public const string CreatedAt = "created_at";
    public const string UpdatedAt = "updated_at";
    public const string Cnf = "cnf";
    public const string Jkt = "jkt";
    public const string DeviceCode = "device_code";
    public const string UserCode = "user_code";
    public const string VerificationUri = "verification_uri";
    public const string VerificationUriComplete = "verification_uri_complete";
    public const string Interval = "interval";

    // Custom parameter
    public const string RequireReferenceToken = "require_reference_token";
    public const string AuthorizationCodeExpiration = "authorization_code_expiration";
    public const string DeviceCodeExpiration = "device_code_expiration";
    public const string AccessTokenExpiration = "access_token_expiration";
    public const string RefreshTokenExpiration = "refresh_token_expiration";
    public const string ClientSecretExpiration = "client_secret_expiration";
    public const string JwksExpiration = "jwks_expiration";
    public const string RequestUriExpiration = "request_uri_expiration";
}