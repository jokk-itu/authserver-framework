namespace AuthServer.Authentication.OAuthToken;
public class OAuthTokenException : Exception
{
    public string Error { get; private init; }
    public string ErrorDescription { get; private init; }
    public string Scheme { get; private init; }
    public string? DPoPNonce { get; private init; }
    public string? Scope { get; private init; }

    public OAuthTokenException(string error, string errorDescription, string scheme, string? scope = null, string? dPoPNonce = null)
    {
        Error = error;
        ErrorDescription = errorDescription;
        Scheme = scheme;
        Scope = scope;
        DPoPNonce = dPoPNonce;
    }
}