using AuthServer.Core.Request;

namespace AuthServer.TokenByGrant;
internal record AuthorizationPendingProcessError(string DeviceCodeId, string Error, string ErrorDescription, ResultCode ResultCode)
    : ProcessError(Error, ErrorDescription, ResultCode);