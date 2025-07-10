using AuthServer.Authorization.Models;
using AuthServer.Core;
using AuthServer.Core.Request;

namespace AuthServer.DeviceAuthorization;

internal static class DeviceAuthorizationError
{
    public static readonly ProcessError MultipleOrNoneClientMethod =
        new(ErrorCode.InvalidClient, "only one client authentication method must be used", ResultCode.BadRequest);

    public static readonly ProcessError InvalidClient =
        new(ErrorCode.InvalidClient, "client could not be authenticated", ResultCode.BadRequest);
    
    public static readonly ProcessError UnauthorizedForGrant =
        new(ErrorCode.InvalidGrant, "client is unauthorized for device_code", ResultCode.BadRequest);
    
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

    public static readonly ProcessError InvalidAcrValues =
        new(ErrorCode.InvalidRequest, "acr_values is invalid", ResultCode.BadRequest);
    
    public static readonly ProcessError InvalidGrantManagement =
        new(ErrorCode.InvalidRequest, "grant_management_action or grant_id is invalid", ResultCode.BadRequest);
    
    public static readonly ProcessError InvalidGrantId =
        new(ErrorCode.InvalidGrantId, "grant_id is invalid", ResultCode.BadRequest);

    public static readonly ProcessError InvalidResource =
        new(ErrorCode.InvalidTarget, "resource is invalid", ResultCode.BadRequest);

    public static readonly ProcessError InvalidRequestAndRequestUri =
        new(ErrorCode.InvalidRequest, "request_uri and request were both provided", ResultCode.BadRequest);

    public static readonly ProcessError InvalidRequestUri =
        new(ErrorCode.InvalidRequestUri, "request_uri is not an absolute well formed uri", ResultCode.BadRequest);

    public static readonly ProcessError UnauthorizedRequestUri =
        new(ErrorCode.InvalidRequestUri, "client has not registered the request_uri", ResultCode.BadRequest);

    public static readonly ProcessError InvalidRequestObjectFromRequestUri =
        new(ErrorCode.InvalidRequestUri, "request_object from reference is invalid", ResultCode.BadRequest);

    public static readonly ProcessError InvalidRequest =
        new(ErrorCode.InvalidRequestObject, "request is invalid", ResultCode.BadRequest);

    public static readonly ProcessError RequestOrRequestUriRequiredAsRequestObject =
        new(ErrorCode.InvalidRequest, "client requires either request or request_uri as request_object", ResultCode.BadRequest);
    
    public static readonly ProcessError DPoPRequired =
        new(ErrorCode.InvalidRequest, "client requires dpop or dpop_jkt", ResultCode.BadRequest);

    public static ProcessError RenewDPoPNonce(string clientId) =>
        new DPoPNonceProcessError(null, clientId, ErrorCode.UseDPoPNonce, "dpop does not contain valid nonce", ResultCode.BadRequest);

    public static ProcessError UseDPoPNonce(string dPoPNonce)
        => new DPoPNonceProcessError(dPoPNonce, null, ErrorCode.UseDPoPNonce, "dpop does not contain valid nonce", ResultCode.BadRequest);

    public static readonly ProcessError InvalidDPoP =
        new(ErrorCode.InvalidRequest, "dpop is invalid", ResultCode.BadRequest);
}