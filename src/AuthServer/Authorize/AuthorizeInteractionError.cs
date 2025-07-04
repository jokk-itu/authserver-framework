using AuthServer.Core.Request;

namespace AuthServer.Authorize;

internal record AuthorizeInteractionError(
    string Error,
    string ErrorDescription,
    ResultCode ResultCode,
    string RequestUri,
    string ClientId) : ProcessError(Error, ErrorDescription, ResultCode)
{
    public string RequestUri { get; } = RequestUri;
    public string ClientId { get; } = ClientId;
}