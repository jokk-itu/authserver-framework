using System.Text.Json;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Repositories.Models;
using AuthServer.Tests.Core;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Authorization;

public class AuthorizationDetailsValidatorTest : BaseUnitTest
{
    public AuthorizationDetailsValidatorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task ValidateAuthorizationDetails_AuthorizationDetailsNotProvided_ExpectEmptyResult(string? authorizationDetails)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationDetailsValidator = serviceProvider.GetRequiredService<IAuthorizationDetailsValidator>();

        // Act
        var result = await authorizationDetailsValidator.ValidateAuthorizationDetails(authorizationDetails, CancellationToken.None);

        // Assert
        Assert.True(result.IsValid);
        Assert.Empty(result.AuthorizationDetails);
    }

    [Fact]
    public async Task ValidateAuthorizationDetails_AuthorizationDetailValidatorIsNull_ExpectNotSupportedError()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(services =>
        {
            var descriptor = services.Single(x => x.ServiceType == typeof(IAuthorizationDetailValidator));
            services.Remove(descriptor);
        });
        var authorizationDetailsValidator = serviceProvider.GetRequiredService<IAuthorizationDetailsValidator>();

        // Act
        var result = await authorizationDetailsValidator.ValidateAuthorizationDetails("[{}]", CancellationToken.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(AuthorizationDetailsError.NotSupported, result.Error);
    }

    [Fact]
    public async Task ValidateAuthorizationDetails_InvalidStructureAuthorizationDetails_ExpectInvalid()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationDetailsValidator = serviceProvider.GetRequiredService<IAuthorizationDetailsValidator>();

        // Act
        var result = await authorizationDetailsValidator.ValidateAuthorizationDetails("[{invalid_structure}]", CancellationToken.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(AuthorizationDetailsError.Invalid, result.Error);
    }

    [Fact]
    public async Task ValidateAuthorizationDetails_InvalidStructureOfTypeAuthorizationDetails_ExpectInvalid()
    {
        // Arrange
        var authorizationDetailValidatorMock = new Mock<IAuthorizationDetailValidator>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationDetailValidatorMock);
        });
        var authorizationDetailsValidator = serviceProvider.GetRequiredService<IAuthorizationDetailsValidator>();

        // Act
        var result = await authorizationDetailsValidator.ValidateAuthorizationDetails(@"[{""type"": ""openid"", ""invalid_property"": ""invalid""}]", CancellationToken.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(AuthorizationDetailsError.Invalid, result.Error);
    }

    [Fact]
    public async Task ValidateAuthorizationDetails_ValidAuthorizationDetails_ExpectValidAuthorizationDetails()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationDetailsValidator = serviceProvider.GetRequiredService<IAuthorizationDetailsValidator>();

        var authorizationDetails = JsonSerializer.Serialize(
            new List<DefaultAuthorizationDetailDto>
            {
                new()
                {
                    Type = AuthorizationDetailTypeConstants.OpenId
                }
            });

        var expectedAuthorizationDetails = new List<string>
        {
            JsonSerializer.Serialize(new DefaultAuthorizationDetailDto
            {
                Type = AuthorizationDetailTypeConstants.OpenId
            })
        };

        // Act
        var result = await authorizationDetailsValidator.ValidateAuthorizationDetails(authorizationDetails, CancellationToken.None);

        // Assert
        Assert.True(result.IsValid);
        Assert.Null(result.Error);
        Assert.Equivalent(expectedAuthorizationDetails, result.AuthorizationDetails);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task AuthorizeAuthorizationDetails_AuthorizationDetailsNotProvided_ExpectEmptyResult(string? authorizationDetails)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationDetailsValidator = serviceProvider.GetRequiredService<IAuthorizationDetailsValidator>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);

        // Act
        var result = await authorizationDetailsValidator.AuthorizeAuthorizationDetails(authorizationDetails, client.Id, CancellationToken.None);

        // Assert
        Assert.True(result.IsValid);
        Assert.Empty(result.AuthorizationDetails);
    }

    [Fact]
    public async Task AuthorizeAuthorizationDetails_AuthorizationDetailValidatorIsNull_ExpectNotSupportedError()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider(services =>
        {
            var descriptor = services.Single(x => x.ServiceType == typeof(IAuthorizationDetailValidator));
            services.Remove(descriptor);
        });
        var authorizationDetailsValidator = serviceProvider.GetRequiredService<IAuthorizationDetailsValidator>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);

        // Act
        var result = await authorizationDetailsValidator.AuthorizeAuthorizationDetails("[{}]", client.Id, CancellationToken.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(AuthorizationDetailsError.NotSupported, result.Error);
    }

    [Fact]
    public async Task AuthorizeAuthorizationDetails_InvalidStructureAuthorizationDetails_ExpectInvalid()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationDetailsValidator = serviceProvider.GetRequiredService<IAuthorizationDetailsValidator>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);

        // Act
        var result = await authorizationDetailsValidator.AuthorizeAuthorizationDetails("[{invalid_structure}]", client.Id, CancellationToken.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(AuthorizationDetailsError.Invalid, result.Error);
    }

    [Fact]
    public async Task AuthorizeAuthorizationDetails_InvalidStructureOfTypeAuthorizationDetails_ExpectInvalid()
    {
        // Arrange
        var authorizationDetailValidatorMock = new Mock<IAuthorizationDetailValidator>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(authorizationDetailValidatorMock);
        });
        var authorizationDetailsValidator = serviceProvider.GetRequiredService<IAuthorizationDetailsValidator>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);

        // Act
        var result = await authorizationDetailsValidator.AuthorizeAuthorizationDetails(@"[{""type"": ""openid"", ""invalid_property"": ""invalid""}]", client.Id, CancellationToken.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(AuthorizationDetailsError.Invalid, result.Error);
    }

    [Fact]
    public async Task AuthorizeAuthorizationDetails_ClientIsNotAuthorizedForAuthorizationDetails_ExpectNotAuthorizedForClient()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationDetailsValidator = serviceProvider.GetRequiredService<IAuthorizationDetailsValidator>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);

        var authorizationDetails = JsonSerializer.Serialize(new List<DefaultAuthorizationDetailDto>
        {
            new()
            {
                Type = AuthorizationDetailTypeConstants.OpenId
            }
        });

        // Act
        var result = await authorizationDetailsValidator.AuthorizeAuthorizationDetails(authorizationDetails, client.Id, CancellationToken.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(AuthorizationDetailsError.NotAuthorizedForClient, result.Error);
    }

    [Fact]
    public async Task AuthorizeAuthorizationDetails_ResourceIsNotAuthorizedForAuthorizationDetails_ExpectNotAuthorizedForResource()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationDetailsValidator = serviceProvider.GetRequiredService<IAuthorizationDetailsValidator>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var openIdAuthorizationDetailType = await GetAuthorizationDetailType(AuthorizationDetailTypeConstants.OpenId);
        client.AuthorizationDetailTypes.Add(openIdAuthorizationDetailType);
        await AddEntity(client);

        var authorizationDetails = JsonSerializer.Serialize(new List<DefaultAuthorizationDetailDto>
        {
            new()
            {
                Type = AuthorizationDetailTypeConstants.OpenId,
                Locations = ["https://api.authserver.dk"]
            }
        });

        // Act
        var result = await authorizationDetailsValidator.AuthorizeAuthorizationDetails(authorizationDetails, client.Id, CancellationToken.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Equal(AuthorizationDetailsError.NotAuthorizedForResource, result.Error);
    }

    [Fact]
    public async Task AuthorizeAuthorizationDetails_AuthorizedAuthorizationDetails_ExpectAuthorizedAuthorizationDetails()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var authorizationDetailsValidator = serviceProvider.GetRequiredService<IAuthorizationDetailsValidator>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var openIdAuthorizationDetailType = await GetAuthorizationDetailType(AuthorizationDetailTypeConstants.OpenId);
        client.AuthorizationDetailTypes.Add(openIdAuthorizationDetailType);
        await AddEntity(client);

        var resource = new Client("web-api", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            ClientUri = "https://api.authserver.dk"
        };
        resource.AuthorizationDetailTypes.Add(openIdAuthorizationDetailType);
        await AddEntity(resource);

        var authorizationDetails = JsonSerializer.Serialize(new List<DefaultAuthorizationDetailDto>
        {
            new()
            {
                Type = AuthorizationDetailTypeConstants.OpenId,
                Locations = [resource.ClientUri!]
            }
        });

        var expectedAuthorizationDetails = new List<string>
        {
            JsonSerializer.Serialize(new DefaultAuthorizationDetailDto
            {
                Type = AuthorizationDetailTypeConstants.OpenId,
                Locations = [resource.ClientUri!]
            })
        };

        // Act
        var result = await authorizationDetailsValidator.AuthorizeAuthorizationDetails(authorizationDetails, client.Id, CancellationToken.None);

        // Assert
        Assert.True(result.IsValid);
        Assert.Null(result.Error);
        Assert.Equivalent(expectedAuthorizationDetails, result.AuthorizationDetails);
    }
}