using AuthServer.Authentication.Abstractions;
using AuthServer.Tests.Core;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Text;
using System.Text.Json;
using System.Web;
using AuthServer.EndSession;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.EndSession;

public class EndSessionUserAccessorTest : BaseUnitTest
{
    private readonly CookieOptions cookieOptions;

    public EndSessionUserAccessorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
        cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            IsEssential = true,
            SameSite = SameSiteMode.Lax
        };
    }

    [Fact]
    public void SetUser_UserAlreadySet_ExpectInvalidOperationException()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var dataProtector = serviceProvider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(EndSessionUserAccessor.DataProtectorName);

        var endSessionUserAccessor = serviceProvider.GetRequiredService<IUserAccessor<EndSessionUser>>();
        var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
        httpContextAccessor.HttpContext = new DefaultHttpContext();

        var endSessionUser = new EndSessionUser(Guid.NewGuid().ToString(), true);
        var encryptedEndSessionUser = GetEncryptedAuthorizeCookie(dataProtector, endSessionUser);
        httpContextAccessor.HttpContext.Response.Cookies.Append(EndSessionUserAccessor.Cookie, encryptedEndSessionUser, cookieOptions);

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => endSessionUserAccessor.SetUser(endSessionUser));
    }

    [Fact]
    public void SetUser_UserNotSet_ExpectUserIsSet()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var dataProtector = serviceProvider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(EndSessionUserAccessor.DataProtectorName);

        var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
        httpContextAccessor.HttpContext = new DefaultHttpContext();

        var endSessionUserAccessor = serviceProvider.GetRequiredService<IUserAccessor<EndSessionUser>>();
        var endSessionUser = new EndSessionUser(Guid.NewGuid().ToString(), true);

        // Act
        endSessionUserAccessor.SetUser(endSessionUser);

        // Assert
        var headers = httpContextAccessor.HttpContext!.Response.GetTypedHeaders();
        var encryptedEndSessionUser = HttpUtility.UrlDecode(headers.SetCookie.First().Value.Value!);
        Assert.Equal(endSessionUser.SubjectIdentifier, GetDecryptedAuthorizeCookie(dataProtector, encryptedEndSessionUser).SubjectIdentifier);
    }

    [Fact]
    public void TrySetUser_UserAlreadySet_ExpectUserIsNotSet()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var dataProtector = serviceProvider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(EndSessionUserAccessor.DataProtectorName);

        var endSessionUserAccessor = serviceProvider.GetRequiredService<IUserAccessor<EndSessionUser>>();
        var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
        httpContextAccessor.HttpContext = new DefaultHttpContext();

        var endSessionUser = new EndSessionUser(Guid.NewGuid().ToString(), true);
        var encryptedEndSessionUser = GetEncryptedAuthorizeCookie(dataProtector, endSessionUser);
        httpContextAccessor.HttpContext.Response.Cookies.Append(EndSessionUserAccessor.Cookie, encryptedEndSessionUser, cookieOptions);

        // Act
        var otherUser = new EndSessionUser(Guid.NewGuid().ToString(), true);
        var hasBeenSet = endSessionUserAccessor.TrySetUser(otherUser);

        // Assert
        Assert.False(hasBeenSet);
        var headers = httpContextAccessor.HttpContext!.Response.GetTypedHeaders();
        var decryptedEndSessionUser = GetDecryptedAuthorizeCookie(dataProtector, HttpUtility.UrlDecode(headers.SetCookie.First().Value.Value!));
        Assert.Equal(endSessionUser.SubjectIdentifier, decryptedEndSessionUser.SubjectIdentifier);
    }

    [Fact]
    public void TrySetUser_UserNotSet_ExpectUserIsSet()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var dataProtector = serviceProvider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(EndSessionUserAccessor.DataProtectorName);

        var endSessionUserAccessor = serviceProvider.GetRequiredService<IUserAccessor<EndSessionUser>>();
        var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
        httpContextAccessor.HttpContext = new DefaultHttpContext();

        var endSessionUser = new EndSessionUser(Guid.NewGuid().ToString(), true);

        // Act
        var hasBeenSet = endSessionUserAccessor.TrySetUser(endSessionUser);

        // Assert
        Assert.True(hasBeenSet);
        var headers = httpContextAccessor.HttpContext!.Response.GetTypedHeaders();
        var decryptedEndSessionUser = GetDecryptedAuthorizeCookie(dataProtector, HttpUtility.UrlDecode(headers.SetCookie.First().Value.Value!));
        Assert.Equal(endSessionUser.SubjectIdentifier, decryptedEndSessionUser.SubjectIdentifier);
    }

    [Fact]
    public void GetUser_UserIsSet_ExpectUser()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var dataProtector = serviceProvider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(EndSessionUserAccessor.DataProtectorName);

        var endSessionUserAccessor = serviceProvider.GetRequiredService<IUserAccessor<EndSessionUser>>();
        var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
        httpContextAccessor.HttpContext = new DefaultHttpContext();

        var endSessionUser = new EndSessionUser(Guid.NewGuid().ToString(), true);
        var encryptedEndSessionUser = GetEncryptedAuthorizeCookie(dataProtector, endSessionUser);
        httpContextAccessor.HttpContext.Request.Cookies = HttpContextHelper.GetRequestCookies(
            new Dictionary<string, string>
            {
                { EndSessionUserAccessor.Cookie, encryptedEndSessionUser }
            });

        // Act
        var decryptedEndSessionUser = endSessionUserAccessor.GetUser();

        // Assert
        Assert.Equal(endSessionUser.SubjectIdentifier, decryptedEndSessionUser.SubjectIdentifier);
    }

    [Fact]
    public void GetUser_UserIsNotSet_ExpectInvalidOperationException()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();

        var endSessionUserAccessor = serviceProvider.GetRequiredService<IUserAccessor<EndSessionUser>>();
        var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
        httpContextAccessor.HttpContext = new DefaultHttpContext();

        // Act & Assert
        Assert.Throws<InvalidOperationException>(endSessionUserAccessor.GetUser);
    }

    [Fact]
    public void TryGetUser_UserIsSet_ExpectUser()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var dataProtector = serviceProvider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(EndSessionUserAccessor.DataProtectorName);

        var endSessionUserAccessor = serviceProvider.GetRequiredService<IUserAccessor<EndSessionUser>>();
        var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
        httpContextAccessor.HttpContext = new DefaultHttpContext();

        var endSessionUser = new EndSessionUser(Guid.NewGuid().ToString(), true);
        var encryptedEndSessionUser = GetEncryptedAuthorizeCookie(dataProtector, endSessionUser);
        httpContextAccessor.HttpContext.Request.Cookies = HttpContextHelper.GetRequestCookies(
            new Dictionary<string, string>
            {
                { EndSessionUserAccessor.Cookie, encryptedEndSessionUser }
            });

        // Act
        var decryptedEndSessionUser = endSessionUserAccessor.TryGetUser();

        // Assert
        Assert.NotNull(decryptedEndSessionUser);
        Assert.Equal(endSessionUser.SubjectIdentifier, decryptedEndSessionUser.SubjectIdentifier);
    }

    [Fact]
    public void TryGetUser_UserIsNotSet_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();

        var endSessionUserAccessor = serviceProvider.GetRequiredService<IUserAccessor<EndSessionUser>>();
        var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
        httpContextAccessor.HttpContext = new DefaultHttpContext();

        // Act
        var user = endSessionUserAccessor.TryGetUser();

        // Assert
        Assert.Null(user);
    }

    [Fact]
    public void Clear_UserIsSet_ExpectCleared()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var dataProtector = serviceProvider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(EndSessionUserAccessor.DataProtectorName);

        var endSessionUserAccessor = serviceProvider.GetRequiredService<IUserAccessor<EndSessionUser>>();
        var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
        httpContextAccessor.HttpContext = new DefaultHttpContext();

        var endSessionUser = new EndSessionUser(Guid.NewGuid().ToString(), true);
        var encryptedEndSessionUser = GetEncryptedAuthorizeCookie(dataProtector, endSessionUser);
        httpContextAccessor.HttpContext.Request.Cookies = HttpContextHelper.GetRequestCookies(
            new Dictionary<string, string>
            {
                { EndSessionUserAccessor.Cookie, encryptedEndSessionUser }
            });

        // Act
        var isCleared = endSessionUserAccessor.ClearUser();

        // Assert
        Assert.True(isCleared);
    }

    [Fact]
    public void Clear_UserIsNotSet_ExpectNotCleared()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();

        var endSessionUserAccessor = serviceProvider.GetRequiredService<IUserAccessor<EndSessionUser>>();
        var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
        httpContextAccessor.HttpContext = new DefaultHttpContext();

        // Act
        var isCleared = endSessionUserAccessor.ClearUser();

        // Assert
        Assert.False(isCleared);
    }

    private static string GetEncryptedAuthorizeCookie(IDataProtector dataProtector, EndSessionUser endSessionUser)
    {
        var endSessionUserBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(endSessionUser));
        var encryptedEndSessionUser = dataProtector.Protect(endSessionUserBytes);
        return Convert.ToBase64String(encryptedEndSessionUser);
    }

    private static EndSessionUser GetDecryptedAuthorizeCookie(IDataProtector dataProtector, string endSessionUser)
    {
        var decryptedEndSessionUser = dataProtector.Unprotect(Convert.FromBase64String(endSessionUser));
        return JsonSerializer.Deserialize<EndSessionUser>(Encoding.UTF8.GetString(decryptedEndSessionUser))!;
    }
}