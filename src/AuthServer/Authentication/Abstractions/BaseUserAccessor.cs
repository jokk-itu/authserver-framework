using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using System.Text.Json;
using System.Text;

namespace AuthServer.Authentication.Abstractions;

internal abstract class BaseUserAccessor<TUser> : IUserAccessor<TUser> where TUser : class
{
    private readonly CookieOptions _cookieOptions;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IDataProtector _dataProtector;

    protected abstract string CookieName { get; }

    protected BaseUserAccessor(
        IHttpContextAccessor httpContextAccessor,
        IDataProtector dataProtector)
    {
        _dataProtector = dataProtector;
        _httpContextAccessor = httpContextAccessor;

        _cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            IsEssential = true,
            Secure = true,
            SameSite = SameSiteMode.Lax,
            MaxAge = TimeSpan.FromMinutes(5)
        };
    }

    public TUser GetUser() => InternalTryGetUser() ?? throw new InvalidOperationException("User is not set");

    public TUser? TryGetUser() => InternalTryGetUser();

    public void SetUser(TUser user)
    {
        if (HasSetCookie())
        {
            throw new InvalidOperationException("User is already set");
        }

        InternalSetUser(user);
    }

    public bool TrySetUser(TUser user)
    {
        if (HasSetCookie())
        {
            return false;
        }

        InternalSetUser(user);
        return true;
    }

    public bool ClearUser()
    {
        if (InternalTryGetUser() is null)
        {
            return false;
        }

        _httpContextAccessor.HttpContext!.Response.Cookies.Delete(CookieName, _cookieOptions);
        return true;
    }

    private TUser? InternalTryGetUser()
    {
        var hasCookie = _httpContextAccessor.HttpContext!.Request.Cookies.TryGetValue(CookieName, out var encryptedUser);
        if (!hasCookie)
        {
            return null;
        }

        var decryptedUser = _dataProtector.Unprotect(Convert.FromBase64String(encryptedUser!));
        var user = JsonSerializer.Deserialize<TUser>(Encoding.UTF8.GetString(decryptedUser));
        return user!;
    }

    private void InternalSetUser(TUser user)
    {
        var userBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(user));
        var encryptedUser = _dataProtector.Protect(userBytes);
        _httpContextAccessor.HttpContext!.Response.Cookies.Append(CookieName, Convert.ToBase64String(encryptedUser), _cookieOptions);
    }

    private bool HasSetCookie() => _httpContextAccessor.HttpContext!.Response.Headers.SetCookie.Any(x => x != null && x.StartsWith(CookieName));
}