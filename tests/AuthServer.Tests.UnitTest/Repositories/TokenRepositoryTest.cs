using AuthServer.Constants;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Repositories.Abstractions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Repositories;
public class TokenRepositoryTest : BaseUnitTest
{
    public TokenRepositoryTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task RevokeExpiredTokens_ExpiredAndActiveTokens_ExpectDeletedExpiredTokens()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();

        var client = new Client("webapp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var expiredToken = new RegistrationToken(client, "webapp", DiscoveryDocument.Issuer, ScopeConstants.Register);
        expiredToken.Revoke();

        var activeToken = new RegistrationToken(client, "webapp", DiscoveryDocument.Issuer, ScopeConstants.Register);

        await AddEntity(expiredToken);
        await AddEntity(activeToken);

        var tokenRepository = serviceProvider.GetRequiredService<ITokenRepository>();

        // Act
        await tokenRepository.RevokeExpiredTokens(2, CancellationToken.None);
        await SaveChangesAsync();

        // Assert
        Assert.Null(await IdentityContext.Set<Token>().FirstOrDefaultAsync(x => x.Id == expiredToken.Id));
        Assert.NotNull(await IdentityContext.Set<Token>().FirstOrDefaultAsync(x => x.Id == activeToken.Id));
    }
}
