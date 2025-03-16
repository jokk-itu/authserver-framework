using AuthServer.Authentication.Abstractions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;

namespace AuthServer.Authorize;

internal class AuthorizeUserAccessor : BaseUserAccessor<AuthorizeUser>
{
    protected override string CookieName { get; }

    public const string Cookie = "AuthorizeUser";
    public const string DataProtectorName = "AuthorizeUser";

    public AuthorizeUserAccessor(IHttpContextAccessor httpContextAccessor, IDataProtectionProvider dataProtectionProvider)
        : base(httpContextAccessor, dataProtectionProvider.CreateProtector(DataProtectorName))
    {
        CookieName = Cookie;
    }
}