namespace AuthServer.Core.Request;
public class ProcessError(string Error, string ErrorDescription, ResultCode ResultCode)
{
    public string Error { get; } = Error;
    public string ErrorDescription { get; } = ErrorDescription;
    public ResultCode ResultCode { get; } = ResultCode;

    public IDictionary<string, string> ToDictionary()
    {
        return new Dictionary<string, string>
        {
            { Parameter.Error, Error },
            { Parameter.ErrorDescription, ErrorDescription }
        };
    }
}