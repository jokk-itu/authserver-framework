using AuthServer.Authentication.Abstractions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;

namespace AuthServer.EndSession;

internal class EndSessionUserAccessor : BaseUserAccessor<EndSessionUser>
{
    protected override string CookieName { get; }

    public const string Cookie = "EndSessionUser";
    public const string DataProtectorName = "EndSessionUser";

    public EndSessionUserAccessor(IHttpContextAccessor httpContextAccessor, IDataProtectionProvider dataProtectionProvider)
        : base(httpContextAccessor, dataProtectionProvider.CreateProtector(DataProtectorName))
    {
        CookieName = Cookie;
    }
}