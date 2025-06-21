using System.Text;
using AuthServer.Authentication.Models;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.DeviceAuthorization;
using AuthServer.Enums;
using AuthServer.Extensions;
using AuthServer.TokenDecoders;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.DeviceAuthorization;

public class DeviceAuthorizationRequestAccessorTest : BaseUnitTest
{
    public DeviceAuthorizationRequestAccessorTest(ITestOutputHelper outputHelper) : base(outputHelper)
    {
    }
    
    [Theory]
    [InlineData("", "")]
    [InlineData(null, null)]
    public async Task GetRequest_EmptyStringParametersBody_ExpectValues(string? value, string? expectedValue)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var requestAccessor = serviceProvider.GetRequiredService<IRequestAccessor<DeviceAuthorizationRequest>>();
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Method = "POST",
                Form = new FormCollection(new Dictionary<string, StringValues>
                {
                    { Parameter.MaxAge, value },
                    { Parameter.CodeChallenge, value },
                    { Parameter.CodeChallengeMethod, value },
                    { Parameter.Nonce, value },
                    { Parameter.GrantId, value },
                    { Parameter.GrantManagementAction, value },
                    { Parameter.Request, value },
                    { Parameter.RequestUri, value },
                    { Parameter.ClientId, value },
                    { Parameter.ClientSecret, value },
                    { Parameter.ClientAssertion, value },
                    { Parameter.ClientAssertionType, value },
                }),
                Headers =
                {
                    Authorization = $"Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes($"{value.FormUrlEncode()}:{value.FormUrlEncode()}"))}"
                }
            }
        };

        httpContext.Request.Headers[Parameter.DPoP] = value;

        // Act
        var request = await requestAccessor.GetRequest(httpContext.Request);

        // Assert
        Assert.Equal(expectedValue, request.MaxAge);
        Assert.Equal(expectedValue, request.CodeChallenge);
        Assert.Equal(expectedValue, request.CodeChallengeMethod);
        Assert.Equal(expectedValue, request.Nonce);
        Assert.Equal(expectedValue, request.GrantId);
        Assert.Equal(expectedValue, request.GrantManagementAction);
        Assert.Equal(expectedValue, request.DPoP);
        Assert.Equal(expectedValue, request.RequestObject);
        Assert.Equal(expectedValue, request.RequestUri);
        Assert.Empty(request.ClientAuthentications);
    }

    [Fact]
    public async Task GetRequest_NormalStringParameters_ExpectValues()
    {
        // Arrange
        const string value = "random_value";
        var serviceProvider = BuildServiceProvider();
        var requestAccessor = serviceProvider.GetRequiredService<IRequestAccessor<DeviceAuthorizationRequest>>();
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Method = "POST",
                Form = new FormCollection(new Dictionary<string, StringValues>
                {   
                    { Parameter.MaxAge, value },
                    { Parameter.CodeChallenge, value },
                    { Parameter.CodeChallengeMethod, value },
                    { Parameter.Nonce, value },
                    { Parameter.GrantId, value },
                    { Parameter.GrantManagementAction, value },
                    { Parameter.Request, value },
                    { Parameter.RequestUri, value }
                })
            }
        };

        httpContext.Request.Headers[Parameter.DPoP] = value;

        // Act
        var request = await requestAccessor.GetRequest(httpContext.Request);

        // Assert
        Assert.Equal(value, request.MaxAge);
        Assert.Equal(value, request.CodeChallenge);
        Assert.Equal(value, request.CodeChallengeMethod);
        Assert.Equal(value, request.Nonce);
        Assert.Equal(value, request.GrantId);
        Assert.Equal(value, request.GrantManagementAction);
        Assert.Equal(value, request.DPoP);
        Assert.Equal(value, request.RequestObject);
        Assert.Equal(value, request.RequestUri);
        Assert.Empty(request.ClientAuthentications);
    }

    [Fact]
    public async Task GetRequest_NormalStringParametersForClientAuthentication_ExpectValues()
    {
        // Arrange
        const string value = "random_value";
        var serviceProvider = BuildServiceProvider();
        var requestAccessor = serviceProvider.GetRequiredService<IRequestAccessor<DeviceAuthorizationRequest>>();
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Method = "POST",
                Form = new FormCollection(new Dictionary<string, StringValues>
                {
                    { Parameter.ClientId, value },
                    { Parameter.ClientSecret, value },
                    { Parameter.ClientAssertion, value },
                    { Parameter.ClientAssertionType, value },
                }),
                Headers =
                {
                    Authorization = $"Basic {Convert.ToBase64String(Encoding.UTF8.GetBytes($"{value.FormUrlEncode()}:{value.FormUrlEncode()}"))}"
                }
            }
        };

        // Act
        var request = await requestAccessor.GetRequest(httpContext.Request);

        // Assert
        Assert.Collection(request.ClientAuthentications,
            clientAuthentication =>
            {
                Assert.IsType<ClientSecretAuthentication>(clientAuthentication);
                var clientSecretAuthentication = (clientAuthentication as ClientSecretAuthentication)!;
                Assert.Equal(value, clientSecretAuthentication.ClientId);
                Assert.Equal(value, clientSecretAuthentication.ClientSecret);
                Assert.Equal(TokenEndpointAuthMethod.ClientSecretBasic, clientSecretAuthentication.Method);
            },
            clientAuthentication =>
            {
                Assert.IsType<ClientSecretAuthentication>(clientAuthentication);
                var clientSecretAuthentication = (clientAuthentication as ClientSecretAuthentication)!;
                Assert.Equal(value, clientSecretAuthentication.ClientId);
                Assert.Equal(value, clientSecretAuthentication.ClientSecret);
                Assert.Equal(TokenEndpointAuthMethod.ClientSecretPost, clientSecretAuthentication.Method);
            },
            clientAuthentication =>
            {
                Assert.IsType<ClientAssertionAuthentication>(clientAuthentication);
                var clientAssertionAuthentication = (clientAuthentication as ClientAssertionAuthentication)!;
                Assert.Equal(value, clientAssertionAuthentication.ClientId);
                Assert.Equal(value, clientAssertionAuthentication.ClientAssertion);
                Assert.Equal(value, clientAssertionAuthentication.ClientAssertionType);
                Assert.Equal(ClientTokenAudience.PushedAuthorizationEndpoint, clientAssertionAuthentication.Audience);
                Assert.Equal(TokenEndpointAuthMethod.PrivateKeyJwt, clientAssertionAuthentication.Method);
            });
    }

    [Fact]
    public async Task GetRequest_SpaceDelimitedParametersBody_ExpectValues()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var requestAccessor = serviceProvider.GetRequiredService<IRequestAccessor<DeviceAuthorizationRequest>>();
        const string value = "three random values";
        string[] expectedValue = ["three", "random", "values"];
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Method = "POST",
                Form = new FormCollection(new Dictionary<string, StringValues>
                {
                    { Parameter.Scope, value },
                    { Parameter.AcrValues, value },
                    { Parameter.Resource, value },
                })
            }
        };

        // Act
        var request = await requestAccessor.GetRequest(httpContext.Request);

        // Assert
        Assert.Equal(expectedValue, request.Scope);
        Assert.Equal(expectedValue, request.AcrValues);
        Assert.Equal(expectedValue, request.Resource);
    }

    [Theory]
    [InlineData("", 0)]
    [InlineData(null, 0)]
    public async Task GetRequest_SpaceDelimitedParametersBody_ExpectZeroValues(string? value, int expectedCount)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var requestAccessor = serviceProvider.GetRequiredService<IRequestAccessor<DeviceAuthorizationRequest>>();
        var httpContext = new DefaultHttpContext
        {
            Request =
            {
                Method = "POST",
                Form = new FormCollection(new Dictionary<string, StringValues>
                {
                    { Parameter.Scope, value },
                    { Parameter.AcrValues, value },
                    { Parameter.Resource, value },
                })
            }
        };

        // Act
        var request = await requestAccessor.GetRequest(httpContext.Request);

        // Assert
        Assert.Equal(expectedCount, request.Scope.Count);
        Assert.Equal(expectedCount, request.AcrValues.Count);
        Assert.Equal(expectedCount, request.Resource.Count);
    }
}