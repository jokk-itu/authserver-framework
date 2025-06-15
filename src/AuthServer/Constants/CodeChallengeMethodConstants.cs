namespace AuthServer.Constants;
public static class CodeChallengeMethodConstants
{
    public const string S256 = "S256";
    public const string S384 = "S384";
    public const string S512 = "S512";
    public static readonly string[] CodeChallengeMethods = [S256, S384, S512];
}