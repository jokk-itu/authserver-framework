using AuthServer.Core.Request;

namespace AuthServer.Authorization.Models;
internal record RenewDPoPNonceProcessError(string ClientId, string Error, string ErrorDescription, ResultCode ResultCode)
    : ProcessError(Error, ErrorDescription, ResultCode);