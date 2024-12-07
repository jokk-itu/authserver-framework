namespace AuthServer.Core.Request;
public class ProcessError(string Error, string ErrorDescription, ResultCode ResultCode)
{
    public string Error = Error;
    public string ErrorDescription = ErrorDescription;
    public ResultCode ResultCode = ResultCode;

    public IDictionary<string, string> ToDictionary()
    {
        return new Dictionary<string, string>
        {
            { Parameter.Error, Error },
            { Parameter.ErrorDescription, ErrorDescription }
        };
    }
}