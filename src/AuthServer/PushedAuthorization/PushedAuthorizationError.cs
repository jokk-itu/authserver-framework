using AuthServer.Authorization.Models;
using AuthServer.Core.Request;
using AuthServer.Core;

namespace AuthServer.PushedAuthorization;

internal static class PushedAuthorizationError
{
    public static readonly ProcessError InvalidState =
        new(ErrorCode.InvalidRequest, "state must not be null or empty", ResultCode.BadRequest);

    public static readonly ProcessError MultipleOrNoneClientMethod =
        new(ErrorCode.InvalidClient, "only one client authentication method must be used", ResultCode.BadRequest);

    public static readonly ProcessError InvalidClient =
        new(ErrorCode.InvalidClient, "client could not be authenticated", ResultCode.BadRequest);

    public static readonly ProcessError InvalidRedirectUri =
        new(ErrorCode.InvalidRequest, "redirect_uri must not be null or empty", ResultCode.BadRequest);

    public static readonly ProcessError UnauthorizedRedirectUri =
        new(ErrorCode.UnauthorizedClient, "client is unauthorized for redirect_uri", ResultCode.BadRequest);

    public static readonly ProcessError InvalidResponseMode =
        new(ErrorCode.InvalidRequest, "response_mode is invalid", ResultCode.BadRequest);

    public static readonly ProcessError InvalidResponseType =
        new(ErrorCode.InvalidRequest, "response_type is invalid", ResultCode.BadRequest);

    public static readonly ProcessError UnauthorizedResponseType =
        new(ErrorCode.UnauthorizedClient, "client is unauthorized for authorization_code", ResultCode.BadRequest);

    public static readonly ProcessError InvalidDisplay =
        new(ErrorCode.InvalidRequest, "display is invalid", ResultCode.BadRequest);

    public static readonly ProcessError InvalidNonce =
        new(ErrorCode.InvalidRequest, "nonce must not be null or empty", ResultCode.BadRequest);

    public static readonly ProcessError ReplayNonce =
        new(ErrorCode.InvalidRequest, "nonce replay attack detected", ResultCode.BadRequest);

    public static readonly ProcessError InvalidCodeChallengeMethod =
        new(ErrorCode.InvalidRequest, "code_challenge_method is invalid", ResultCode.BadRequest);

    public static readonly ProcessError InvalidCodeChallenge =
        new(ErrorCode.InvalidRequest, "code_challenge is invalid", ResultCode.BadRequest);

    public static readonly ProcessError InvalidOpenIdScope =
        new(ErrorCode.InvalidScope, "openid is required", ResultCode.BadRequest);

    public static readonly ProcessError UnauthorizedScope =
        new(ErrorCode.UnauthorizedClient, "client is unauthorized for scope", ResultCode.BadRequest);

    public static readonly ProcessError InvalidMaxAge =
        new(ErrorCode.InvalidRequest, "max_age is invalid", ResultCode.BadRequest);

    public static readonly ProcessError InvalidIdTokenHint =
        new(ErrorCode.InvalidRequest, "id_token_hint is invalid", ResultCode.BadRequest);

    public static readonly ProcessError InvalidPrompt =
        new(ErrorCode.InvalidRequest, "prompt is invalid", ResultCode.BadRequest);

    public static readonly ProcessError InvalidAcrValues =
        new(ErrorCode.InvalidRequest, "acr_values is invalid", ResultCode.BadRequest);
    
    public static readonly ProcessError InvalidGrantManagement =
        new(ErrorCode.InvalidRequest, "grant_management_action or grant_id is invalid", ResultCode.BadRequest);
    
    public static readonly ProcessError InvalidGrantId =
        new(ErrorCode.InvalidGrantId, "grant_id is invalid", ResultCode.BadRequest);

    public static readonly ProcessError InvalidDPoPJktMatch =
        new(ErrorCode.InvalidDPoPProof, "dpop_jkt does not match jkt of dpop", ResultCode.BadRequest);

    public static readonly ProcessError DPoPRequired =
        new(ErrorCode.InvalidRequest, "client requires dpop or dpop_jkt", ResultCode.BadRequest);

    public static ProcessError RenewDPoPNonce(string clientId) =>
        new DPoPNonceProcessError(null, clientId, ErrorCode.UseDPoPNonce, "dpop does not contain valid nonce", ResultCode.BadRequest);

    public static readonly ProcessError InvalidDPoP =
        new(ErrorCode.InvalidDPoPProof, "dpop is invalid", ResultCode.BadRequest);

    public static readonly ProcessError InvalidRequest =
        new(ErrorCode.InvalidRequestObject, "request is invalid", ResultCode.BadRequest);

    public static readonly ProcessError RequestRequiredAsRequestObject =
        new(ErrorCode.InvalidRequest, "client requires request as request_object", ResultCode.BadRequest);

    public static readonly ProcessError InvalidResource =
        new(ErrorCode.InvalidTarget, "resource is invalid", ResultCode.BadRequest);
}