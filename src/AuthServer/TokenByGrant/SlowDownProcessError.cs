using AuthServer.Core.Request;

namespace AuthServer.TokenByGrant;
internal record SlowDownProcessError(string DeviceCodeId, string Error, string ErrorDescription, ResultCode ResultCode)
    : ProcessError(Error, ErrorDescription, ResultCode);