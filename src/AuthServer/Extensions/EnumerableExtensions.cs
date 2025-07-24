namespace AuthServer.Extensions;
internal static class EnumerableExtensions
{
    /// <summary>
    /// 
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="left"></param>
    /// <param name="right"></param>
    /// <returns></returns>
    public static bool IsDisjoint<T>(this IEnumerable<T> left, IEnumerable<T> right)
    {
        var enumeratedSuperSet = right.ToList();
        if (enumeratedSuperSet.Count == 0)
        {
            return true;
        }

        return !left.Intersect(enumeratedSuperSet).Any();
    }

    /// <summary>
    /// 
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="left"></param>
    /// <param name="right"></param>
    /// <returns></returns>
    public static bool IsIntersected<T>(this IEnumerable<T> left, IEnumerable<T> right)
    {
        var enumeratedSuperSet = right.ToList();
        if (enumeratedSuperSet.Count == 0)
        {
            return false;
        }

        return left.Intersect(enumeratedSuperSet).Any();
    }

    /// <summary>
    /// 
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="subset"></param>
    /// <param name="superset"></param>
    /// <returns></returns>
    public static bool IsSubset<T>(this IEnumerable<T> subset, IEnumerable<T> superset)
    {
        var enumeratedSuperSet = superset.ToList();
        var enumeratedSubset = subset.ToList();
        if (enumeratedSuperSet.Count == 0 || enumeratedSubset.Count == 0)
        {
            return false;
        }

        return !enumeratedSubset.Except(enumeratedSuperSet).Any();
    }

    /// <summary>
    /// 
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="subset"></param>
    /// <param name="superset"></param>
    /// <returns></returns>
    public static bool IsNotSubset<T>(this IEnumerable<T> subset, IEnumerable<T> superset)
    {
        var enumeratedSuperSet = superset.ToList();
        var enumeratedSubset = subset.ToList();
        if (enumeratedSuperSet.Count == 0 || enumeratedSubset.Count == 0)
        {
            return true;
        }

        return enumeratedSubset.Except(enumeratedSuperSet).Any();
    }
}