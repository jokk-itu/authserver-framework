using AuthServer.Core.Request;

namespace AuthServer.Authorization.Models;

internal record DPoPNonceProcessError(string? DPoPNonce, string? ClientId, string Error, string ErrorDescription, ResultCode ResultCode)
    : ProcessError(Error, ErrorDescription, ResultCode);