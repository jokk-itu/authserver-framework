using AuthServer.Core.Request;

namespace AuthServer.Authorize;

internal record PersistRequestUriError(
    string Error,
    string ErrorDescription,
    ResultCode ResultCode,
    AuthorizeRequest AuthorizeRequest) : ProcessError(Error, ErrorDescription, ResultCode)
{
    public AuthorizeRequest AuthorizeRequest { get; } = AuthorizeRequest;
}
