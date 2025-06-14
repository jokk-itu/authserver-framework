using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace AuthServer.Extensions;

internal static class QueryCollectionExtensions
{
    public static string? GetValue(this IQueryCollection queryCollection, string key)
    {
        queryCollection.TryGetValue(key, out var value);
        return value == StringValues.Empty ? null : value.ToString();
    }

    public static IReadOnlyCollection<string> GetSpaceDelimitedValue(this IQueryCollection queryCollection, string key)
    {
        queryCollection.TryGetValue(key, out var value);
        var hasValue = !StringValues.IsNullOrEmpty(value);
        return !hasValue ? [] : value.ToString().Split(' ');
    }

    public static IReadOnlyCollection<string> GetCollectionValue(this IQueryCollection queryCollection, string key)
    {
        queryCollection.TryGetValue(key, out var value);
        var hasValue = !StringValues.IsNullOrEmpty(value);
        return (!hasValue ? [] : value.ToArray())!;
    }
}