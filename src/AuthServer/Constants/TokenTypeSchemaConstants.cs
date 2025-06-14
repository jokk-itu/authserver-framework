namespace AuthServer.Constants;
internal static class TokenTypeSchemaConstants
{
    public const string Bearer = "Bearer";
    public const string DPoP = "DPoP";

    public static readonly string[] TokenTypeSchemas = [Bearer, DPoP];
}