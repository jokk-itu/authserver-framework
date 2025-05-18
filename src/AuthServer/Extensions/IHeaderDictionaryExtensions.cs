using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace AuthServer.Extensions;
internal static class IHeaderDictionaryExtensions
{
    public static string? GetValue(this IHeaderDictionary headers, string key)
    {
        headers.TryGetValue(key, out var value);
        return value == StringValues.Empty ? null : value.ToString();
    }
}
