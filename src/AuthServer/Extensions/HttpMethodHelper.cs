namespace AuthServer.Extensions;
internal static class HttpMethodHelper
{
    public static bool TryParse(string httpMethod, out HttpMethod? parsedHttpMethod)
    {
        try
        {
            parsedHttpMethod = HttpMethod.Parse(httpMethod);
            return true;
        }
        catch (ArgumentException)
        {
            parsedHttpMethod = null;
            return false;
        }
    }
}