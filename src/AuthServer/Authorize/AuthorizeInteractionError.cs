using AuthServer.Core.Request;

namespace AuthServer.Authorize;

public record AuthorizeInteractionError(string Error, string ErrorDescription, ResultCode ResultCode, string RequestUri, string ClientId) : ProcessError(Error, ErrorDescription, ResultCode);