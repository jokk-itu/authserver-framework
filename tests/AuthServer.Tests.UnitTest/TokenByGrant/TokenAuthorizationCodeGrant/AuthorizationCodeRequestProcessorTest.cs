﻿using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Tests.Core;
using AuthServer.TokenBuilders;
using AuthServer.TokenBuilders.Abstractions;
using AuthServer.TokenByGrant;
using AuthServer.TokenByGrant.TokenAuthorizationCodeGrant;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.TokenByGrant.TokenAuthorizationCodeGrant;

public class AuthorizationCodeRequestProcessorTest : BaseUnitTest
{
    public AuthorizationCodeRequestProcessorTest(ITestOutputHelper outputHelper) : base(outputHelper)
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
        var authorizationCodeProcessor = serviceProvider.GetRequiredService<IRequestProcessor<AuthorizationCodeValidatedRequest, TokenResponse>>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            AccessTokenExpiration = 3600
        };
        var authorizationCodeGrantType = await GetGrantType(GrantTypeConstants.AuthorizationCode);
        var refreshTokenGrantType = await GetGrantType(GrantTypeConstants.RefreshToken);
        client.GrantTypes.Add(authorizationCodeGrantType);
        client.GrantTypes.Add(refreshTokenGrantType);

        var authorizationGrant = await GetAuthorizationGrant(client);
        var authorizationCode = authorizationGrant.AuthorizationCodes.Single();
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

        var tokenRequest = new AuthorizationCodeValidatedRequest
        {
            ClientId = client.Id,
            AuthorizationGrantId = authorizationGrant.Id,
            AuthorizationCodeId = authorizationCode.Id,
            Scope = [ScopeConstants.OpenId],
            Resource = [weatherClient.ClientUri!]
        };

        // Act
        var tokenResponse = await authorizationCodeProcessor.Process(tokenRequest, CancellationToken.None);

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
        var authorizationCodeProcessor = serviceProvider.GetRequiredService<IRequestProcessor<AuthorizationCodeValidatedRequest, TokenResponse>>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            AccessTokenExpiration = 3600
        };
        var authorizationCodeGrantType = await GetGrantType(GrantTypeConstants.AuthorizationCode);
        client.GrantTypes.Add(authorizationCodeGrantType);

        var authorizationGrant = await GetAuthorizationGrant(client);
        var authorizationCode = authorizationGrant.AuthorizationCodes.Single();
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

        var tokenRequest = new AuthorizationCodeValidatedRequest
        {
            ClientId = client.Id,
            AuthorizationGrantId = authorizationGrant.Id,
            AuthorizationCodeId = authorizationCode.Id,
            Scope = [ScopeConstants.OpenId],
            Resource = [weatherClient.ClientUri!]
        };

        // Act
        var tokenResponse = await authorizationCodeProcessor.Process(tokenRequest, CancellationToken.None);

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

    private async Task<AuthorizationCodeGrant> GetAuthorizationGrant(Client client)
    {
        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);

        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);
        var authorizationCode = new AuthorizationCode(authorizationGrant, 60);
        typeof(Code)
            .GetProperty(nameof(Code.RawValue))!
            .SetValue(authorizationCode, "value");

        await AddEntity(authorizationCode);

        return authorizationGrant;
    }
}