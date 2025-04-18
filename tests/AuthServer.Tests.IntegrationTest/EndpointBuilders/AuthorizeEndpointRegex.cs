using System.Text.RegularExpressions;

namespace AuthServer.Tests.IntegrationTest.EndpointBuilders;
internal partial class AuthorizeEndpointRegex
{
    [GeneratedRegex("<form method=\"post\" action=\"([^\"]+)\">", RegexOptions.None, 100)]
    private static partial Regex FormActionRegex();

    [GeneratedRegex("<input type=\"hidden\" name=\"iss\" value=\"([^\"]+)\" \\/>", RegexOptions.None, 100)]
    private static partial Regex IssuerFieldRegex();

    [GeneratedRegex("<input type=\"hidden\" name=\"code\" value=\"([^\"]+)\" \\/>", RegexOptions.None, 100)]
    private static partial Regex CodeFieldRegex();

    [GeneratedRegex("<input type=\"hidden\" name=\"error\" value=\"([^\"]+)\" \\/>", RegexOptions.None, 100)]
    private static partial Regex ErrorFieldRegex();

    [GeneratedRegex("<input type=\"hidden\" name=\"error_description\" value=\"([^\"]+)\" \\/>", RegexOptions.None, 100)]
    private static partial Regex ErrorDescriptionRegex();

    [GeneratedRegex("<input type=\"hidden\" name=\"state\" value=\"([^\"]+)\" \\/>", RegexOptions.None, 100)]
    private static partial Regex StateFieldRegex();

    public static string? GetFormAction(string input)
        => FormActionRegex().Match(input).Groups.ElementAtOrDefault<Group>(1)?.Captures.ElementAtOrDefault(0)?.Value;

    public static string? GetIssuerField(string input)
        => IssuerFieldRegex().Match(input).Groups.ElementAtOrDefault<Group>(1)?.Captures.ElementAtOrDefault(0)?.Value;

    public static string? GetCodeField(string input)
        => CodeFieldRegex().Match(input).Groups.ElementAtOrDefault<Group>(1)?.Captures.ElementAtOrDefault(0)?.Value;

    public static string? GetErrorField(string input)
        => ErrorFieldRegex().Match(input).Groups.ElementAtOrDefault<Group>(1)?.Captures.ElementAtOrDefault(0)?.Value;

    public static string? GetErrorDescription(string input)
        => ErrorDescriptionRegex().Match(input).Groups.ElementAtOrDefault<Group>(1)?.Captures.ElementAtOrDefault(0)?.Value;

    public static string? GetStateField(string input)
        => StateFieldRegex().Match(input).Groups.ElementAtOrDefault<Group>(1)?.Captures.ElementAtOrDefault(0)?.Value;
}
