namespace AuthServer.Extensions;
internal static class EnumerableExtensions
{
    /// <summary>
    /// Is subSet of superSet.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="subSet"></param>
    /// <param name="superSet"></param>
    /// <returns>false if subSet contains any input that is not found in superSet or if source is empty</returns>
    public static bool IsSubset<T>(this IEnumerable<T> subSet, IEnumerable<T> superSet)
        => subSet.Except(superSet).Any();
}