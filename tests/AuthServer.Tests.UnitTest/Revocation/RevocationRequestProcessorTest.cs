using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Revocation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Revocation;
public class RevocationRequestProcessorTest : BaseUnitTest
{
    public RevocationRequestProcessorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task Process_ReferenceToken_ExpectRevoked()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var revocationRequestProcessor = serviceProvider.GetRequiredService<IRequestProcessor<RevocationValidatedRequest, Unit>>();
        var client = new Client("webapp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var token = new ClientAccessToken(client, "resource", DiscoveryDocument.Issuer, "scope", 1);
        await AddEntity(token);

        // Act
        await revocationRequestProcessor.Process(new RevocationValidatedRequest
        {
            Jti = token.Id.ToString()
        }, CancellationToken.None);

        // Assert
        Assert.NotNull(token.RevokedAt);
    }

    [Fact]
    public async Task Process_ReferenceTokenAlreadyRevoked_ExpectNoOperation()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var revocationRequestProcessor = serviceProvider.GetRequiredService<IRequestProcessor<RevocationValidatedRequest, Unit>>();
        var client = new Client("webapp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var token = new ClientAccessToken(client, "resource", DiscoveryDocument.Issuer, "scope", 1);
        token.Revoke();
        var revokedAt = token.RevokedAt;
        await AddEntity(token);

        // Act
        await revocationRequestProcessor.Process(new RevocationValidatedRequest
        {
            Jti = token.Id.ToString()
        }, CancellationToken.None);

        // Assert
        Assert.NotNull(token.RevokedAt);
        Assert.Equal(revokedAt, token.RevokedAt);
    }

    [Fact]
    public async Task Process_Jwt_ExpectRevoked()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var revocationRequestProcessor = serviceProvider.GetRequiredService<IRequestProcessor<RevocationValidatedRequest, Unit>>();

        var client = new Client("webapp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var token = new ClientAccessToken(client, "resource", DiscoveryDocument.Issuer, "scope", 1);
        await AddEntity(token);

        var tokenHandler = new JsonWebTokenHandler();
        var jwt = tokenHandler.CreateToken(new SecurityTokenDescriptor
        {
            Claims = new Dictionary<string, object>
            {
                { ClaimNameConstants.Jti, token.Id }
            }
        });

        // Act
        await revocationRequestProcessor.Process(new RevocationValidatedRequest
        {
            Jti = token.Id.ToString()
        }, CancellationToken.None);

        // Assert
        Assert.NotNull(token.RevokedAt);
    }
}
