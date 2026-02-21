using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Repositories.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Repositories;

public class AuthorizationCodeRepositoryTest : BaseUnitTest
{
    public AuthorizationCodeRepositoryTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task IsActiveAuthorizationCode_NonExistingCode_ExpectFalse()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var repository = serviceProvider.GetRequiredService<IAuthorizationCodeRepository>();

        // Act
        var result = await repository.IsActiveAuthorizationCode("non-existing-code", CancellationToken.None);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task IsActiveAuthorizationCode_RedeemedCode_ExpectFalse()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var repository = serviceProvider.GetRequiredService<IAuthorizationCodeRepository>();

        var authorizationCode = await GetAuthorizationCode();
        authorizationCode.Redeem();
        await SaveChangesAsync();

        // Act
        var result = await repository.IsActiveAuthorizationCode(authorizationCode.Id, CancellationToken.None);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task IsActiveAuthorizationCode_Expired_ExpectFalse()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var repository = serviceProvider.GetRequiredService<IAuthorizationCodeRepository>();

        var authorizationCode = await GetAuthorizationCode();
        typeof(Code)
            .GetProperty(nameof(Code.ExpiresAt))!
            .SetValue(authorizationCode, DateTime.UtcNow.AddSeconds(-60));

        await SaveChangesAsync();

        // Act
        var result = await repository.IsActiveAuthorizationCode(authorizationCode.Id, CancellationToken.None);

        // Assert
        Assert.False(result);
    }

    [Theory]
    [InlineData(-2)]
    [InlineData(60)]
    public async Task IsActiveAuthorizationCode_ValidCode_ExpectTrue(int authorizationCodeExpiration)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var repository = serviceProvider.GetRequiredService<IAuthorizationCodeRepository>();

        var authorizationCode = await GetAuthorizationCode(authorizationCodeExpiration);

        // Act
        var result = await repository.IsActiveAuthorizationCode(authorizationCode.Id, CancellationToken.None);

        // Assert
        Assert.True(result);
    }

    private async Task<AuthorizationCode> GetAuthorizationCode(int authorizationCodeExpiration = 60)
    {
        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            AuthorizationCodeExpiration = authorizationCodeExpiration
        };
        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationCodeGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);
        var authorizationCode = new AuthorizationCode(authorizationCodeGrant, client.AuthorizationCodeExpiration.Value);
        authorizationCode.SetRawValue("raw-code");
        await AddEntity(authorizationCode);

        return authorizationCode;
    }
}