namespace AuthServer.Constants;

public static class GrantManagementActionConstants
{
    public const string Query = "query";
    public const string Revoke = "revoke";
    public const string Replace = "replace";
    public const string Merge = "merge";
    public const string Create = "create";

    public static readonly string[] GrantManagementActions = [ Query, Revoke, Replace, Merge, Create ];
}