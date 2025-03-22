using System.Net;
using System.Runtime.Intrinsics.X86;
using AuthServer.Authentication.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Tests.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Authentication;

public class ClientJwkServiceTest(ITestOutputHelper outputHelper) : BaseUnitTest(outputHelper)
{
    [Fact]
    public async Task GetKeys_NoJwks_ExpectNoKeys()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var clientJwkService = serviceProvider.GetRequiredService<IClientJwkService>();
        var client = new Client("PinguBasicWebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        await AddEntity(client);

        // Act
        var keys = await clientJwkService.GetKeys(client.Id, JsonWebKeyUseNames.Sig, CancellationToken.None);

        // Assert
        Assert.Empty(keys);
    }

    [Theory]
    [InlineData(JsonWebKeyUseNames.Sig)]
    [InlineData(JsonWebKeyUseNames.Enc)]
    public async Task GetKeys_JwksWithNoExpiration_ExpectCachedKeys(string use)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var clientJwkService = serviceProvider.GetRequiredService<IClientJwkService>();
        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var client = new Client("PinguPrivateKeyJwtWebApp", ApplicationType.Web, TokenEndpointAuthMethod.PrivateKeyJwt)
        {
            Jwks = clientJwks.PublicJwks
        };
        await AddEntity(client);

        // Act
        var keys = await clientJwkService.GetKeys(client.Id, use, CancellationToken.None);

        // Assert
        var key = Assert.Single(keys);
        Assert.Equal(use, key.Use);
    }
    
    [Theory]
    [InlineData(JsonWebKeyUseNames.Sig)]
    [InlineData(JsonWebKeyUseNames.Enc)]
    public async Task GetKeys_JwksWithinExpiration_ExpectCachedKeys(string use)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var clientJwkService = serviceProvider.GetRequiredService<IClientJwkService>();
        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var client = new Client("PinguPrivateKeyJwtWebApp", ApplicationType.Web, TokenEndpointAuthMethod.PrivateKeyJwt)
        {
            Jwks = clientJwks.PublicJwks,
            JwksExpiresAt = DateTime.Now.AddSeconds(60)
        };
        await AddEntity(client);

        // Act
        var keys = await clientJwkService.GetKeys(client.Id, use, CancellationToken.None);

        // Assert
        var key = Assert.Single(keys);
        Assert.Equal(use, key.Use);
    }

    [Theory]
    [InlineData(JsonWebKeyUseNames.Sig)]
    [InlineData(JsonWebKeyUseNames.Enc)]
    public async Task GetKeys_JwksNotWithinExpiration_ExpectNoKeys(string use)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var clientJwkService = serviceProvider.GetRequiredService<IClientJwkService>();
        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var client = new Client("PinguPrivateKeyJwtWebApp", ApplicationType.Web, TokenEndpointAuthMethod.PrivateKeyJwt)
        {
            Jwks = clientJwks.PublicJwks,
            JwksExpiresAt = DateTime.UtcNow.AddSeconds(-60)
        };
        await AddEntity(client);

        // Act
        var keys = await clientJwkService.GetKeys(client.Id, use, CancellationToken.None);

        // Assert
        Assert.Empty(keys);
    }
    
    [Theory]
    [InlineData(JsonWebKeyUseNames.Sig)]
    [InlineData(JsonWebKeyUseNames.Enc)]
    public async Task GetKeys_JwksUriWithinExpiration_ExpectCachedKeys(string use)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var clientJwkService = serviceProvider.GetRequiredService<IClientJwkService>();
        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var client = new Client("PinguPrivateKeyJwtWebApp", ApplicationType.Web, TokenEndpointAuthMethod.PrivateKeyJwt)
        {
            Jwks = clientJwks.PublicJwks,
            JwksUri = "https://localhost:5000/.well-known/jwks",
            JwksExpiration = 60,
            JwksExpiresAt = DateTime.UtcNow.AddSeconds(60)
        };
        await AddEntity(client);

        // Act
        var keys = await clientJwkService.GetKeys(client.Id, use, CancellationToken.None);

        // Assert
        var key = Assert.Single(keys);
        Assert.Equal(use, key.Use);
    }

    [Theory]
    [InlineData(JsonWebKeyUseNames.Sig)]
    [InlineData(JsonWebKeyUseNames.Enc)]
    public async Task GetKeys_JwksUriNotWithinExpirationRefreshPrivateKeys_ExpectNoKeys(string use)
    {
        // Arrange
        var httpClientFactory = new Mock<IHttpClientFactory>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            var requestHandler = new DelegatingHandlerStub(
                ClientJwkBuilder.GetClientJwks().PrivateJwks,
                MimeTypeConstants.Json,
                HttpStatusCode.OK);

            httpClientFactory
                .Setup(x => x.CreateClient(HttpClientNameConstants.Client))
                .Returns(new HttpClient(requestHandler))
                .Verifiable();

            services.AddSingletonMock(httpClientFactory);
        });
        var clientJwkService = serviceProvider.GetRequiredService<IClientJwkService>();
        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var client = new Client("PinguPrivateKeyJwtWebApp", ApplicationType.Web, TokenEndpointAuthMethod.PrivateKeyJwt)
        {
            Jwks = clientJwks.PublicJwks,
            JwksUri = "https://localhost:5000/.well-known/jwks",
            JwksExpiration = 60,
            JwksExpiresAt = DateTime.UtcNow.AddSeconds(-60)
        };
        await AddEntity(client);

        // Act
        var keys = await clientJwkService.GetKeys(client.Id, use, CancellationToken.None);

        // Assert
        Assert.Empty(keys);
        httpClientFactory.Verify();
    }

    [Theory]
    [InlineData(JsonWebKeyUseNames.Sig)]
    [InlineData(JsonWebKeyUseNames.Enc)]
    public async Task GetKeys_JwksUriNotWithinExpirationRefreshNewKeys_ExpectKeys(string use)
    {
        // Arrange
        var httpClientFactory = new Mock<IHttpClientFactory>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            var requestHandler = new DelegatingHandlerStub(
                ClientJwkBuilder.GetClientJwks().PublicJwks,
                MimeTypeConstants.Json,
                HttpStatusCode.OK);

            httpClientFactory
                .Setup(x => x.CreateClient(HttpClientNameConstants.Client))
                .Returns(new HttpClient(requestHandler))
                .Verifiable();

            services.AddSingletonMock(httpClientFactory);
        });
        var clientJwkService = serviceProvider.GetRequiredService<IClientJwkService>();
        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var client = new Client("PinguPrivateKeyJwtWebApp", ApplicationType.Web, TokenEndpointAuthMethod.PrivateKeyJwt)
        {
            Jwks = clientJwks.PublicJwks,
            JwksUri = "https://localhost:5000/.well-known/jwks",
            JwksExpiration = 60,
            JwksExpiresAt = DateTime.UtcNow.AddSeconds(-60)
        };
        await AddEntity(client);

        // Act
        var keys = await clientJwkService.GetKeys(client.Id, use, CancellationToken.None);

        // Assert
        var key = Assert.Single(keys);
        Assert.Equal(use, key.Use);
        httpClientFactory.Verify();
    }

    [Fact]
    public async Task GetEncryptionKey_OneEncryptionKey_EncryptionKey()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var clientJwkService = serviceProvider.GetRequiredService<IClientJwkService>();
        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var client = new Client("PinguPrivateKeyJwtWebApp", ApplicationType.Web, TokenEndpointAuthMethod.PrivateKeyJwt)
        {
            Jwks = clientJwks.PublicJwks
        };
        await AddEntity(client);

        // Act
        var encryptionKey = await clientJwkService.GetEncryptionKey(client.Id, CancellationToken.None);

        // Assert
        Assert.NotNull(encryptionKey);
        Assert.Equal(JsonWebKeyUseNames.Enc, encryptionKey.Use);
    }

    [Fact]
    public async Task GetEncryptionKey_NoEncryptionKey_Null()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var clientJwkService = serviceProvider.GetRequiredService<IClientJwkService>();
        var client = new Client("PinguBasicWebApp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        await AddEntity(client);

        // Act
        var encryptionKey = await clientJwkService.GetEncryptionKey(client.Id, CancellationToken.None);

        // Assert
        Assert.Null(encryptionKey);
    }

    [Theory]
    [InlineData(JsonWebKeyUseNames.Sig)]
    [InlineData(JsonWebKeyUseNames.Enc)]
    public async Task GetJwks_RefreshKeysWithValidJwksUri_ExpectKeys(string use)
    {
        // Arrange
        var httpClientFactory = new Mock<IHttpClientFactory>();
        var response = ClientJwkBuilder.GetClientJwks().PublicJwks;
        var serviceProvider = BuildServiceProvider(services =>
        {
            var requestHandler = new DelegatingHandlerStub(
                response,
                MimeTypeConstants.Json,
                HttpStatusCode.OK);

            httpClientFactory
                .Setup(x => x.CreateClient(HttpClientNameConstants.Client))
                .Returns(new HttpClient(requestHandler))
                .Verifiable();

            services.AddSingletonMock(httpClientFactory);
        });
        var clientJwkService = serviceProvider.GetRequiredService<IClientJwkService>();
        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var client = new Client("PinguPrivateKeyJwtWebApp", ApplicationType.Web, TokenEndpointAuthMethod.PrivateKeyJwt)
        {
            Jwks = clientJwks.PublicJwks,
            JwksUri = "https://localhost:5000/.well-known/jwks",
            JwksExpiration = 60,
            JwksExpiresAt = DateTime.UtcNow.AddSeconds(-60)
        };
        await AddEntity(client);

        // Act
        var jwksRaw = await clientJwkService.GetJwks(client.JwksUri, CancellationToken.None);

        // Assert
        httpClientFactory.Verify();
        Assert.Equal(response, jwksRaw);
    }

    [Fact]
    public async Task GetJwks_RefreshKeysWithInvalidJwksUri_ExpectNull()
    {
        // Arrange
        var httpClientFactory = new Mock<IHttpClientFactory>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            var requestHandler = new DelegatingHandlerStub(
                "Unexpected error occurred",
                MimeTypeConstants.Text,
                HttpStatusCode.InternalServerError);

            httpClientFactory
                .Setup(x => x.CreateClient(HttpClientNameConstants.Client))
                .Returns(new HttpClient(requestHandler))
                .Verifiable();

            services.AddSingletonMock(httpClientFactory);
        });
        var clientJwkService = serviceProvider.GetRequiredService<IClientJwkService>();
        var clientJwks = ClientJwkBuilder.GetClientJwks();
        var client = new Client("PinguPrivateKeyJwtWebApp", ApplicationType.Web, TokenEndpointAuthMethod.PrivateKeyJwt)
        {
            Jwks = clientJwks.PublicJwks,
            JwksUri = "https://localhost:5000/.well-known/jwks",
            JwksExpiration = 60,
            JwksExpiresAt = DateTime.UtcNow.AddSeconds(-60)
        };
        await AddEntity(client);

        // Act
        var jwksRaw = await clientJwkService.GetJwks(client.JwksUri, CancellationToken.None);

        // Assert
        httpClientFactory.Verify();
        Assert.Null(jwksRaw);
    }
}