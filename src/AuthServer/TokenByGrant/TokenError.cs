using AuthServer.Authorization.Models;
using AuthServer.Core;
using AuthServer.Core.Request;

namespace AuthServer.TokenByGrant;

internal static class TokenError
{
    public static readonly ProcessError UnsupportedGrantType =
        new(ErrorCode.UnsupportedGrantType, "grant_type is unsupported", ResultCode.BadRequest);

    public static readonly ProcessError InvalidCodeVerifier =
        new(ErrorCode.InvalidRequest, "code_verifier is invalid", ResultCode.BadRequest);

    public static readonly ProcessError MultipleOrNoneClientMethod = 
        new(ErrorCode.InvalidClient, "multiple or none client authentication methods detected", ResultCode.BadRequest);

    public static readonly ProcessError InvalidClient =
        new(ErrorCode.InvalidClient, "client could not be authenticated", ResultCode.BadRequest);

    public static readonly ProcessError UnauthorizedForGrantType =
        new(ErrorCode.UnauthorizedClient, "client is unauthorized for grant_type", ResultCode.BadRequest);

    public static readonly ProcessError UnauthorizedForScope =
        new(ErrorCode.UnauthorizedClient, "client is unauthorized for scope", ResultCode.BadRequest);

    public static readonly ProcessError InvalidResource =
        new(ErrorCode.InvalidTarget, "resource is invalid", ResultCode.BadRequest);

    public static readonly ProcessError InvalidCode =
        new(ErrorCode.InvalidRequest, "code is invalid", ResultCode.BadRequest);

    public static readonly ProcessError InvalidRefreshToken =
        new(ErrorCode.InvalidRequest, "refresh_token is invalid", ResultCode.BadRequest);

    public static readonly ProcessError InvalidRedirectUri =
        new(ErrorCode.InvalidRequest, "redirect_uri is invalid", ResultCode.BadRequest);

    public static readonly ProcessError InvalidGrant =
        new(ErrorCode.InvalidGrant, "grant is invalid", ResultCode.BadRequest);

    public static readonly ProcessError UnauthorizedForRedirectUri =
        new(ErrorCode.UnauthorizedClient, "client is unauthorized for redirect_uri", ResultCode.BadRequest);

    public static readonly ProcessError ConsentRequired =
        new(ErrorCode.ConsentRequired, "consent is required", ResultCode.BadRequest);

    public static readonly ProcessError ScopeExceedsConsentedScope =
        new(ErrorCode.InvalidScope, "scope exceeds consented scope", ResultCode.BadRequest);

    public static readonly ProcessError InvalidScope =
        new(ErrorCode.InvalidRequest, "scope is missing", ResultCode.BadRequest);

    public static readonly ProcessError InvalidDPoPJktMatch =
        new(ErrorCode.InvalidDPoPProof, "dpop_jkt does not match jkt of dpop", ResultCode.BadRequest);

    public static readonly ProcessError InvalidRefreshTokenJktMatch =
        new(ErrorCode.InvalidDPoPProof, "refresh_token jkt does not match jkt of dpop", ResultCode.BadRequest);

    public static readonly ProcessError DPoPRequired =
        new(ErrorCode.InvalidRequest, "client requires dpop or dpop_jkt", ResultCode.BadRequest);

    public static ProcessError UseDPoPNonce(string dPoPNonce)
        => new DPoPNonceProcessError(dPoPNonce, null, ErrorCode.UseDPoPNonce, "dpop does not contain valid nonce", ResultCode.BadRequest);

    public static readonly ProcessError InvalidDPoP =
        new(ErrorCode.InvalidDPoPProof, "dpop is invalid", ResultCode.BadRequest);

    public static ProcessError RenewDPoPNonce(string clientId) =>
        new DPoPNonceProcessError(null, clientId, ErrorCode.UseDPoPNonce, "dpop does not contain valid nonce", ResultCode.BadRequest);
}