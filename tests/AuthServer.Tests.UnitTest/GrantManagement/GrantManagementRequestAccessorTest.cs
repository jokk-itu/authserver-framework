using System.Security.Claims;
using AuthServer.Authentication.OAuthToken;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Helpers;
using AuthServer.RequestAccessors.GrantManagement;
using AuthServer.Tests.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.GrantManagement;

public class GrantManagementRequestAccessorTest : BaseUnitTest
{
    public GrantManagementRequestAccessorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("DELETE")]
    public async Task GetRequest_NoGrantId_ExpectNullGrantId(string method)
    {
        // Arrange
        var token = CryptographyHelper.GetRandomString(32);
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Method = method,
                Scheme = "https",
                Host = new HostString("localhost"),
                Path = $"/connect/grants/",
            }
        };
        var serviceProvider = BuildServiceProvider(services =>
        {
            var authenticationServiceMock = new Mock<IAuthenticationService>();
            var authResult = AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(), OAuthTokenAuthenticationDefaults.AuthenticationScheme));

            authResult.Properties!.StoreTokens(new[]
            {
                new AuthenticationToken { Name = Parameter.AccessToken, Value = token }
            });

            authenticationServiceMock
                .Setup(x => x.AuthenticateAsync(httpContext, OAuthTokenAuthenticationDefaults.AuthenticationScheme))
                .ReturnsAsync(authResult);

            services.AddScopedMock(authenticationServiceMock);
        });
        var requestAccessor = serviceProvider.GetRequiredService<IRequestAccessor<GrantManagementRequest>>();
        httpContext.RequestServices = serviceProvider;
        
        // Act
        var request = await requestAccessor.GetRequest(httpContext.Request);
        
        // Assert
        Assert.Equal(token, request.AccessToken);
        Assert.Null(request.GrantId);
    }
    
    [Theory]
    [InlineData("GET")]
    [InlineData("DELETE")]
    public async Task GetRequest_WithGrantId_ExpectGrantId(string method)
    {
        // Arrange
        var token = CryptographyHelper.GetRandomString(32);
        var grantId = Guid.NewGuid().ToString();
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Method = method,
                Scheme = "https",
                Host = new HostString("localhost"),
                Path = $"/connect/grants/{grantId}",
            }
        };
        var serviceProvider = BuildServiceProvider(services =>
        {
            var authenticationServiceMock = new Mock<IAuthenticationService>();
            var authResult = AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(), OAuthTokenAuthenticationDefaults.AuthenticationScheme));

            authResult.Properties!.StoreTokens(new[]
            {
                new AuthenticationToken { Name = Parameter.AccessToken, Value = token }
            });

            authenticationServiceMock
                .Setup(x => x.AuthenticateAsync(httpContext, OAuthTokenAuthenticationDefaults.AuthenticationScheme))
                .ReturnsAsync(authResult);

            services.AddScopedMock(authenticationServiceMock);
        });
        var requestAccessor = serviceProvider.GetRequiredService<IRequestAccessor<GrantManagementRequest>>();
        httpContext.RequestServices = serviceProvider;
        
        // Act
        var request = await requestAccessor.GetRequest(httpContext.Request);
        
        // Assert
        Assert.Equal(grantId, request.GrantId);
    }
}