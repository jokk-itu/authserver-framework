﻿namespace AuthServer.Core;
public static class ErrorCode
{
    /// <summary>
    /// The request is missing a required parameter.
    /// </summary>
    public const string InvalidRequest = "invalid_request";

    /// <summary>
    /// Client authentication failed.
    /// </summary>
    public const string InvalidClient = "invalid_client";

    /// <summary>
    /// The provided authorization grant or refresh token is 
    /// invalid, expired, revoked, does not match the redirection
    /// URI used in the authorization request, or was issued to another client.
    /// </summary>
    public const string InvalidGrant = "invalid_grant";

    /// <summary>
    /// The provided grant_id is unknown or invalid or unauthorized.
    /// </summary>
    public const string InvalidGrantId = "invalid_grant_id";

    /// <summary>
    /// The authenticated client is not authorized.
    /// </summary>
    public const string UnauthorizedClient = "unauthorized_client";

    /// <summary>
    /// The resource owner or authorization server denied the request.
    /// </summary>
    public const string AccessDenied = "access_denied";

    /// <summary>
    /// The authorization server does not support the given response type.
    /// </summary>
    public const string UnsupportedResponseType = "unsupported_response_type";

    /// <summary>
    /// The authorization grant type is not supported by the authorization server.
    /// </summary>
    public const string UnsupportedGrantType = "unsupported_grant_type";

    /// <summary>
    /// The requested scope is invalid, unknown, malformed, or
    /// exceeds the scope granted by the resource owner.
    /// </summary>
    public const string InvalidScope = "invalid_scope";

    /// <summary>
    /// Corresponds to a 500 status.
    /// </summary>
    public const string ServerError = "server_error";

    /// <summary>
    /// Corresponds to a 503 status.
    /// </summary>
    public const string TemporarilyUnavailable = "temporarily_unavailable";

    /// <summary>
    /// Possibly several properties are invalid when registering or configuring clients.
    /// </summary>
    public const string InvalidClientMetadata = "invalid_client_metadata";

    /// <summary>
    /// The End-User must perform an interaction
    /// </summary>
    public const string InteractionRequired = "interaction_required";

    /// <summary>
    /// The End-User must authenticate
    /// </summary>
    public const string LoginRequired = "login_required";

    /// <summary>
    /// The End-User must select an account
    /// </summary>
    public const string AccountSelectionRequired = "account_selection_required";

    /// <summary>
    /// The End-User must perform consent
    /// </summary>
    public const string ConsentRequired = "consent_required";

    /// <summary>
    /// The request_uri parameter returns an error or contains invalid data
    /// </summary>
    public const string InvalidRequestUri = "invalid_request_uri";

    /// <summary>
    /// The request contains an invalid request object
    /// </summary>
    public const string InvalidRequestObject = "invalid_request_object";

    /// <summary>
    /// The OP does not recognize the token type.
    /// Used in revocation and introspection.
    /// </summary>
    public const string UnsupportedTokenType = "unsupported_token_type";

    /// <summary>
    /// The request contains an invalid resource parameter.
    /// Used in authorize and token endpoints.
    /// </summary>
    public const string InvalidTarget = "invalid_target";

    /// <summary>
    /// The OP is unable to meet the requirements of the Relying Party for the authentication of the End-User.
    /// </summary>
    public const string UnmetAuthenticationRequirements = "unmet_authentication_requirements";

    /// <summary>
    /// The DPoP token does not contain a valid nonce.
    /// </summary>
    public const string UseDPoPNonce = "use_dpop_nonce";

    /// <summary>
    /// The device authorization request is still pending. Keep polling with the same interval.
    /// </summary>
    public const string AuthorizationPending = "authorization_pending";

    /// <summary>
    /// The device authorization request is still pending. Increase the polling interval by 5 seconds and keep polling.
    /// </summary>
    public const string SlowDown = "slow_down";

    /// <summary>
    /// The device code has expired.
    /// </summary>
    public const string ExpiredToken = "expired_token";

    /// <summary>
    /// The token from the Authorization header is invalid.
    /// </summary>
    public const string InvalidToken = "invalid_token";

    /// <summary>
    /// The DPoP proof is invalid.
    /// </summary>
    public const string InvalidDPoPProof = "invalid_dpop_proof";

    /// <summary>
    /// The token has insufficient scope.
    /// </summary>
    public const string InsufficientScope = "insufficient_scope";
}