using AuthServer.Authentication.Abstractions;
using AuthServer.Authorize;
using AuthServer.Tests.Core;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Text;
using System.Text.Json;
using System.Web;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Authorize;

public class AuthorizeUserAccessorTest : BaseUnitTest
{
    public AuthorizeUserAccessorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public void SetUser_UserAlreadySet_ExpectInvalidOperationException()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var dataProtector = serviceProvider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(AuthorizeUserAccessor.DataProtectorName);

        var authorizeUserAccessor = serviceProvider.GetRequiredService<IUserAccessor<AuthorizeUser>>();
        var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
        httpContextAccessor.HttpContext = new DefaultHttpContext();

        var authorizeUser = new AuthorizeUser(Guid.NewGuid().ToString(), true, Guid.NewGuid().ToString());
        var encryptedAuthorizeUser = GetEncryptedAuthorizeCookie(dataProtector, authorizeUser);
        httpContextAccessor.HttpContext.Response.Cookies.Append(AuthorizeUserAccessor.Cookie, encryptedAuthorizeUser);

        // Act & Assert
        Assert.Throws<InvalidOperationException>(() => authorizeUserAccessor.SetUser(authorizeUser));
    }

    [Fact]
    public void SetUser_UserNotSet_ExpectUserIsSet()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var dataProtector = serviceProvider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(AuthorizeUserAccessor.DataProtectorName);

        var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
        httpContextAccessor.HttpContext = new DefaultHttpContext();

        var authorizeUserAccessor = serviceProvider.GetRequiredService<IUserAccessor<AuthorizeUser>>();
        var authorizeUser = new AuthorizeUser(Guid.NewGuid().ToString(), true, Guid.NewGuid().ToString());

        // Act
        authorizeUserAccessor.SetUser(authorizeUser);

        // Assert
        var headers = httpContextAccessor.HttpContext!.Response.GetTypedHeaders();
        var encryptedAuthorizeUser = HttpUtility.UrlDecode(headers.SetCookie.First().Value.Value!);
        Assert.Equal(authorizeUser.SubjectIdentifier, GetDecryptedAuthorizeCookie(dataProtector, encryptedAuthorizeUser).SubjectIdentifier);
    }

    [Fact]
    public void TrySetUser_UserAlreadySet_ExpectUserIsNotSet()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var dataProtector = serviceProvider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(AuthorizeUserAccessor.DataProtectorName);

        var authorizeUserAccessor = serviceProvider.GetRequiredService<IUserAccessor<AuthorizeUser>>();
        var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
        httpContextAccessor.HttpContext = new DefaultHttpContext();

        var authorizeUser = new AuthorizeUser(Guid.NewGuid().ToString(), true, Guid.NewGuid().ToString());
        var encryptedAuthorizeUser = GetEncryptedAuthorizeCookie(dataProtector, authorizeUser);
        httpContextAccessor.HttpContext.Response.Cookies.Append(AuthorizeUserAccessor.Cookie, encryptedAuthorizeUser);

        // Act
        var otherUser = new AuthorizeUser(Guid.NewGuid().ToString(), true, Guid.NewGuid().ToString());
        var hasBeenSet = authorizeUserAccessor.TrySetUser(otherUser);

        // Assert
        Assert.False(hasBeenSet);
        var headers = httpContextAccessor.HttpContext!.Response.GetTypedHeaders();
        var decryptedAuthorizeUser = GetDecryptedAuthorizeCookie(dataProtector, HttpUtility.UrlDecode(headers.SetCookie.First().Value.Value!));
        Assert.Equal(authorizeUser.SubjectIdentifier, decryptedAuthorizeUser.SubjectIdentifier);
    }

    [Fact]
    public void TrySetUser_UserNotSet_ExpectUserIsSet()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var dataProtector = serviceProvider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(AuthorizeUserAccessor.DataProtectorName);

        var authorizeUserAccessor = serviceProvider.GetRequiredService<IUserAccessor<AuthorizeUser>>();
        var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
        httpContextAccessor.HttpContext = new DefaultHttpContext();

        var authorizeUser = new AuthorizeUser(Guid.NewGuid().ToString(), true, Guid.NewGuid().ToString());

        // Act
        var hasBeenSet = authorizeUserAccessor.TrySetUser(authorizeUser);

        // Assert
        Assert.True(hasBeenSet);
        var headers = httpContextAccessor.HttpContext!.Response.GetTypedHeaders();
        var decryptedAuthorizeUser = GetDecryptedAuthorizeCookie(dataProtector, HttpUtility.UrlDecode(headers.SetCookie.First().Value.Value!));
        Assert.Equal(authorizeUser.SubjectIdentifier, decryptedAuthorizeUser.SubjectIdentifier);
    }

    [Fact]
    public void GetUser_UserIsSet_ExpectUser()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var dataProtector = serviceProvider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(AuthorizeUserAccessor.DataProtectorName);

        var authorizeUserAccessor = serviceProvider.GetRequiredService<IUserAccessor<AuthorizeUser>>();
        var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
        httpContextAccessor.HttpContext = new DefaultHttpContext();

        var authorizeUser = new AuthorizeUser(Guid.NewGuid().ToString(), true, Guid.NewGuid().ToString());
        var encryptedAuthorizeUser = GetEncryptedAuthorizeCookie(dataProtector, authorizeUser);
        httpContextAccessor.HttpContext.Request.Cookies = HttpContextHelper.GetRequestCookies(
            new Dictionary<string, string>
            {
                { AuthorizeUserAccessor.Cookie, encryptedAuthorizeUser }
            });

        // Act
        var decryptedAuthorizeUser = authorizeUserAccessor.GetUser();
        
        // Assert
        Assert.Equal(authorizeUser.SubjectIdentifier, decryptedAuthorizeUser.SubjectIdentifier);
    }

    [Fact]
    public void GetUser_UserIsNotSet_ExpectInvalidOperationException()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();

        var authorizeUserAccessor = serviceProvider.GetRequiredService<IUserAccessor<AuthorizeUser>>();
        var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
        httpContextAccessor.HttpContext = new DefaultHttpContext();

        // Act & Assert
        Assert.Throws<InvalidOperationException>(authorizeUserAccessor.GetUser);
    }

    [Fact]
    public void TryGetUser_UserIsSet_ExpectUser()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var dataProtector = serviceProvider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(AuthorizeUserAccessor.DataProtectorName);

        var authorizeUserAccessor = serviceProvider.GetRequiredService<IUserAccessor<AuthorizeUser>>();
        var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
        httpContextAccessor.HttpContext = new DefaultHttpContext();

        var authorizeUser = new AuthorizeUser(Guid.NewGuid().ToString(), true, Guid.NewGuid().ToString());
        var encryptedAuthorizeUser = GetEncryptedAuthorizeCookie(dataProtector, authorizeUser);
        httpContextAccessor.HttpContext.Request.Cookies = HttpContextHelper.GetRequestCookies(
            new Dictionary<string, string>
            {
                { AuthorizeUserAccessor.Cookie, encryptedAuthorizeUser }
            });

        // Act
        var decryptedAuthorizeUser = authorizeUserAccessor.TryGetUser();

        // Assert
        Assert.NotNull(decryptedAuthorizeUser);
        Assert.Equal(authorizeUser.SubjectIdentifier, decryptedAuthorizeUser.SubjectIdentifier);
    }

    [Fact]
    public void TryGetUser_UserIsNotSet_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();

        var authorizeUserAccessor = serviceProvider.GetRequiredService<IUserAccessor<AuthorizeUser>>();
        var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
        httpContextAccessor.HttpContext = new DefaultHttpContext();

        // Act
        var user = authorizeUserAccessor.TryGetUser();

        // Assert
        Assert.Null(user);
    }

    [Fact]
    public void Clear_UserIsSet_ExpectCleared()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var dataProtector = serviceProvider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(AuthorizeUserAccessor.DataProtectorName);

        var authorizeUserAccessor = serviceProvider.GetRequiredService<IUserAccessor<AuthorizeUser>>();
        var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
        httpContextAccessor.HttpContext = new DefaultHttpContext();

        var authorizeUser = new AuthorizeUser(Guid.NewGuid().ToString(), true, Guid.NewGuid().ToString());
        var encryptedAuthorizeUser = GetEncryptedAuthorizeCookie(dataProtector, authorizeUser);
        httpContextAccessor.HttpContext.Request.Cookies = HttpContextHelper.GetRequestCookies(
            new Dictionary<string, string>
            {
                { AuthorizeUserAccessor.Cookie, encryptedAuthorizeUser }
            });

        // Act
        var isCleared = authorizeUserAccessor.ClearUser();

        // Assert
        Assert.True(isCleared);
    }

    [Fact]
    public void Clear_UserIsNotSet_ExpectNotCleared()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();

        var authorizeUserAccessor = serviceProvider.GetRequiredService<IUserAccessor<AuthorizeUser>>();
        var httpContextAccessor = serviceProvider.GetRequiredService<IHttpContextAccessor>();
        httpContextAccessor.HttpContext = new DefaultHttpContext();

        // Act
        var isCleared = authorizeUserAccessor.ClearUser();

        // Assert
        Assert.False(isCleared);
    }

    private static string GetEncryptedAuthorizeCookie(IDataProtector dataProtector, AuthorizeUser authorizeUser)
    {
        var authorizeUserBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(authorizeUser));
        var encryptedAuthorizeUser = dataProtector.Protect(authorizeUserBytes);
        return Convert.ToBase64String(encryptedAuthorizeUser);
    }

    private static AuthorizeUser GetDecryptedAuthorizeCookie(IDataProtector dataProtector, string authorizeUser)
    {
        var decryptedAuthorizeUser = dataProtector.Unprotect(Convert.FromBase64String(authorizeUser));
        return JsonSerializer.Deserialize<AuthorizeUser>(Encoding.UTF8.GetString(decryptedAuthorizeUser))!;
    }
}