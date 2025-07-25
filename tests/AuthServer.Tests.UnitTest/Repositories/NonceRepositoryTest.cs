using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Helpers;
using AuthServer.Repositories.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Repositories;

public class NonceRepositoryTest : BaseUnitTest
{
    public NonceRepositoryTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task IsNonceReplay_NonceExists_ExpectTrue()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var nonceRepository = serviceProvider.GetRequiredService<INonceRepository>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, lowAcr);
        var value = CryptographyHelper.GetRandomString(32);
        var nonce = new AuthorizationGrantNonce(value, value.Sha256(), authorizationGrant);
        await AddEntity(nonce);

        // Act
        var isReplay = await nonceRepository.IsNonceReplay(value, CancellationToken.None);

        // Assert
        Assert.True(isReplay);
    }

    [Fact]
    public async Task IsNonceReplay_NonceDoesNotExist_ExpectFalse()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var nonceRepository = serviceProvider.GetRequiredService<INonceRepository>();

        var value = CryptographyHelper.GetRandomString(32);

        // Act
        var isReplay = await nonceRepository.IsNonceReplay(value, CancellationToken.None);

        // Assert
        Assert.False(isReplay);
    }

    [Fact]
    public async Task GetActiveDPoPNonce_ExpiredNonce_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var nonceRepository = serviceProvider.GetRequiredService<INonceRepository>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var nonce = CryptographyHelper.GetRandomString(16);
        var dPoPNonce = new DPoPNonce(nonce, nonce.Sha256(), client);

        typeof(DPoPNonce)
            .GetProperty(nameof(DPoPNonce.ExpiresAt))!
            .SetValue(dPoPNonce, DateTime.UtcNow.AddSeconds(-60));

        await AddEntity(dPoPNonce);
        
        // Act
        var dPoPNonceValue = await nonceRepository.GetActiveDPoPNonce(client.Id, CancellationToken.None);

        // Assert
        Assert.Null(dPoPNonceValue);
    }

    [Fact]
    public async Task GetActiveDPoPNonce_ClientHasNoDPoPNonce_ExpectNull()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var nonceRepository = serviceProvider.GetRequiredService<INonceRepository>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);

        // Act
        var dPoPNonceValue = await nonceRepository.GetActiveDPoPNonce(client.Id, CancellationToken.None);

        // Assert
        Assert.Null(dPoPNonceValue);
    }

    [Fact]
    public async Task GetActiveDPoPNonce_ClientHasActiveDPoPNonce_ExpectNonceValue()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var nonceRepository = serviceProvider.GetRequiredService<INonceRepository>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var nonce = CryptographyHelper.GetRandomString(16);
        var dPoPNonce = new DPoPNonce(nonce, nonce.Sha256(), client);
        await AddEntity(dPoPNonce);

        // Act
        var dPoPNonceValue = await nonceRepository.GetActiveDPoPNonce(client.Id, CancellationToken.None);

        // Assert
        Assert.Equal(nonce, dPoPNonceValue);
    }

    [Fact]
    public async Task IsDPoPNonce_NonceDoesNotBelongToRequestedClient_ExpectFalse()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var nonceRepository = serviceProvider.GetRequiredService<INonceRepository>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var nonce = CryptographyHelper.GetRandomString(16);
        var dPoPNonce = new DPoPNonce(nonce, nonce.Sha256(), client);
        await AddEntity(dPoPNonce);

        var otherClient = new Client("web-app-2", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(otherClient);

        // Act
        var isDPoPNonce = await nonceRepository.IsDPoPNonce(nonce, otherClient.Id, CancellationToken.None);

        // Assert
        Assert.False(isDPoPNonce);
    }

    [Fact]
    public async Task IsDPoPNonce_NonceDoesNotExist_ExpectFalse()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var nonceRepository = serviceProvider.GetRequiredService<INonceRepository>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var nonce = CryptographyHelper.GetRandomString(16);
        await AddEntity(client);

        // Act
        var isDPoPNonce = await nonceRepository.IsDPoPNonce(nonce, client.Id, CancellationToken.None);

        // Assert
        Assert.False(isDPoPNonce);
    }

    [Fact]
    public async Task IsDPoPNonce_DPoPNonceExistsAndBelongsToClient_ExpectTrue()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var nonceRepository = serviceProvider.GetRequiredService<INonceRepository>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var nonce = CryptographyHelper.GetRandomString(16);
        var dPoPNonce = new DPoPNonce(nonce, nonce.Sha256(), client);
        await AddEntity(dPoPNonce);

        // Act
        var isDPoPNonce = await nonceRepository.IsDPoPNonce(nonce, client.Id, CancellationToken.None);

        // Assert
        Assert.True(isDPoPNonce);
    }

    [Fact]
    public async Task CreateDPoPNonce_CreateDPoPNonce_ExpectDPoPNonceValue()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var nonceRepository = serviceProvider.GetRequiredService<INonceRepository>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);

        // Act
        var dPoPNonceValue = await nonceRepository.CreateDPoPNonce(client.Id, CancellationToken.None);
        await SaveChangesAsync();

        // Assert
        Assert.Equal(client.Nonces.Single().Value, dPoPNonceValue);
    }
}
