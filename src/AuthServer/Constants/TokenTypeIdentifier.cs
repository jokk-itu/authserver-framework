namespace AuthServer.Constants;

public static class TokenTypeIdentifier
{
    public const string AccessToken = "urn:ietf:params:oauth:token-type:access_token";
    public const string IdToken = "urn:ietf:params:oauth:token-type:id_token";

    public static readonly string[] TokenTypeIdentifiers = [ AccessToken, IdToken ];
}