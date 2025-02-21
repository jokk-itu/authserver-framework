namespace AuthServer.Extensions;
internal static class EnumerableExtensions
{
    public static bool IsNotSubset<T>(this IEnumerable<T> subSet, IEnumerable<T> superSet)
        => subSet.Except(superSet).Any();

    public static bool IsSubset<T>(this IEnumerable<T> subSet, IEnumerable<T> superSet)
        => !subSet.Except(superSet).Any();
}