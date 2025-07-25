using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Tests.Core;
using AuthServer.TokenBuilders;
using AuthServer.TokenBuilders.Abstractions;
using AuthServer.TokenByGrant;
using AuthServer.TokenByGrant.TokenDeviceCodeGrant;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.TokenByGrant.TokenDeviceCodeGrant;
public class DeviceCodeRequestProcessorTest : BaseUnitTest
{
    public DeviceCodeRequestProcessorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task Process_WithRefreshToken_ExpectTokenResponse()
    {
        // Arrange
        var accessTokenBuilder = new Mock<ITokenBuilder<GrantAccessTokenArguments>>();
        var refreshTokenBuilder = new Mock<ITokenBuilder<RefreshTokenArguments>>();
        var idTokenBuilder = new Mock<ITokenBuilder<IdTokenArguments>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(accessTokenBuilder);
            services.AddScopedMock(refreshTokenBuilder);
            services.AddScopedMock(idTokenBuilder);
        });
        var deviceCodeProcessor = serviceProvider.GetRequiredService<IRequestProcessor<DeviceCodeValidatedRequest, TokenResponse>>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            AccessTokenExpiration = 3600
        };
        var deviceCodeGrantType = await GetGrantType(GrantTypeConstants.DeviceCode);
        var refreshTokenGrantType = await GetGrantType(GrantTypeConstants.RefreshToken);
        client.GrantTypes.Add(deviceCodeGrantType);
        client.GrantTypes.Add(refreshTokenGrantType);

        var authorizationGrant = await GetDeviceCodeGrant(client);
        var deviceCode = authorizationGrant.DeviceCodes.Single();
        var weatherClient = await GetWeatherClient();

        const string expectedAccessToken = "access_token";
        accessTokenBuilder
            .Setup(x => x.BuildToken(It.IsAny<GrantAccessTokenArguments>(), CancellationToken.None))
            .ReturnsAsync(expectedAccessToken)
            .Verifiable();

        const string expectedRefreshToken = "refresh_token";
        refreshTokenBuilder
            .Setup(x => x.BuildToken(It.IsAny<RefreshTokenArguments>(), CancellationToken.None))
            .ReturnsAsync(expectedRefreshToken)
            .Verifiable();

        const string expectedIdToken = "id_token";
        idTokenBuilder
            .Setup(x => x.BuildToken(It.IsAny<IdTokenArguments>(), CancellationToken.None))
            .ReturnsAsync(expectedIdToken)
            .Verifiable();

        var tokenRequest = new DeviceCodeValidatedRequest
        {
            ClientId = client.Id,
            AuthorizationGrantId = authorizationGrant.Id,
            DeviceCodeId = deviceCode.Id,
            Scope = [ScopeConstants.OpenId],
            Resource = [weatherClient.ClientUri!]
        };

        // Act
        var tokenResponse = await deviceCodeProcessor.Process(tokenRequest, CancellationToken.None);

        // Assert
        Assert.Equal(expectedAccessToken, tokenResponse.AccessToken);
        Assert.Equal(expectedRefreshToken, tokenResponse.RefreshToken);
        Assert.Equal(expectedIdToken, tokenResponse.IdToken);

        accessTokenBuilder.Verify();
        refreshTokenBuilder.Verify();
        idTokenBuilder.Verify();

        Assert.Equal(client.AccessTokenExpiration, tokenResponse.ExpiresIn);
        Assert.Equal(ScopeConstants.OpenId, tokenResponse.Scope);
        Assert.Equal(authorizationGrant.Id, tokenResponse.GrantId);
        Assert.Equal(TokenTypeSchemaConstants.Bearer, tokenResponse.TokenType);
    }

    [Fact]
    public async Task Process_WithoutRefreshToken_ExpectTokenResponse()
    {
        // Arrange
        var accessTokenBuilder = new Mock<ITokenBuilder<GrantAccessTokenArguments>>();
        var idTokenBuilder = new Mock<ITokenBuilder<IdTokenArguments>>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(accessTokenBuilder);
            services.AddScopedMock(idTokenBuilder);
        });
        var deviceCodeProcessor = serviceProvider.GetRequiredService<IRequestProcessor<DeviceCodeValidatedRequest, TokenResponse>>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            AccessTokenExpiration = 3600
        };
        var deviceCodeGrantType = await GetGrantType(GrantTypeConstants.DeviceCode);
        client.GrantTypes.Add(deviceCodeGrantType);

        var authorizationGrant = await GetDeviceCodeGrant(client);
        var deviceCode = authorizationGrant.DeviceCodes.Single();
        var weatherClient = await GetWeatherClient();

        const string expectedAccessToken = "access_token";
        accessTokenBuilder
            .Setup(x => x.BuildToken(It.IsAny<GrantAccessTokenArguments>(), CancellationToken.None))
            .ReturnsAsync(expectedAccessToken)
            .Verifiable();

        const string expectedIdToken = "id_token";
        idTokenBuilder
            .Setup(x => x.BuildToken(It.IsAny<IdTokenArguments>(), CancellationToken.None))
            .ReturnsAsync(expectedIdToken)
            .Verifiable();

        var tokenRequest = new DeviceCodeValidatedRequest
        {
            ClientId = client.Id,
            AuthorizationGrantId = authorizationGrant.Id,
            DeviceCodeId = deviceCode.Id,
            Scope = [ScopeConstants.OpenId],
            Resource = [weatherClient.ClientUri!]
        };

        // Act
        var tokenResponse = await deviceCodeProcessor.Process(tokenRequest, CancellationToken.None);

        // Assert
        Assert.Equal(expectedAccessToken, tokenResponse.AccessToken);
        Assert.Null(tokenResponse.RefreshToken);
        Assert.Equal(expectedIdToken, tokenResponse.IdToken);

        accessTokenBuilder.Verify();
        idTokenBuilder.Verify();

        Assert.Equal(client.AccessTokenExpiration, tokenResponse.ExpiresIn);
        Assert.Equal(ScopeConstants.OpenId, tokenResponse.Scope);
        Assert.Equal(authorizationGrant.Id, tokenResponse.GrantId);
        Assert.Equal(TokenTypeSchemaConstants.Bearer, tokenResponse.TokenType);
    }

    private async Task<Client> GetWeatherClient()
    {
        var weatherClient = new Client("weather-api", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            ClientUri = "https://weather.authserver.dk"
        };
        await AddEntity(weatherClient);

        return weatherClient;
    }

    private async Task<DeviceCodeGrant> GetDeviceCodeGrant(Client client)
    {
        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);

        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new DeviceCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);
        var deviceCode = new DeviceCode(300, 5);
        typeof(Code)
            .GetProperty(nameof(Code.RawValue))!
            .SetValue(deviceCode, "value");

        authorizationGrant.DeviceCodes.Add(deviceCode);

        await AddEntity(authorizationGrant);

        return authorizationGrant;
    }
}
