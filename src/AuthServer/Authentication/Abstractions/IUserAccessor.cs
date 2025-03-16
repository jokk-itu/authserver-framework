namespace AuthServer.Authentication.Abstractions;

internal interface IUserAccessor<TUser> where TUser : class
{
    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    TUser GetUser();

    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    TUser? TryGetUser();

    /// <summary>
    /// 
    /// </summary>
    /// <param name="user"></param>
    void SetUser(TUser user);

    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    bool TrySetUser(TUser user);

    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    bool ClearUser();
}