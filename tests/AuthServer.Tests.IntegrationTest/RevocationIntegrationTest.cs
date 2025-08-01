﻿using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Helpers;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest;

public class RevocationIntegrationTest : BaseIntegrationTest
{
    public RevocationIntegrationTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
        : base(factory, testOutputHelper)
    {
    }

    [Fact]
    public async Task Revocation_ActiveToken_ExpectRevoked()
    {
        // Arrange
        var weatherReadScope = await AddWeatherReadScope();
        var weatherClientSecret = CryptographyHelper.GetRandomString(16);
        var weatherClient = await AddWeatherClient(weatherClientSecret);

        var registerResponse = await RegisterEndpointBuilder
            .WithClientName("worker-app")
            .WithGrantTypes([GrantTypeConstants.ClientCredentials])
            .WithScope([weatherReadScope])
            .WithRequireReferenceToken()
            .Post();

        var tokenResponse = await TokenEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithGrantType(GrantTypeConstants.ClientCredentials)
            .WithResource([weatherClient.ClientUri!])
            .WithScope([weatherReadScope])
            .Post();

        // Act
        await RevocationEndpointBuilder
            .WithClientId(registerResponse.ClientId)
            .WithClientSecret(registerResponse.ClientSecret!)
            .WithToken(tokenResponse.Response!.AccessToken)
            .WithTokenTypeHint(TokenTypeConstants.AccessToken)
            .WithTokenEndpointAuthMethod(TokenEndpointAuthMethod.ClientSecretBasic)
            .Post();

        // Arrange
        var token = await ServiceProvider.GetRequiredService<AuthorizationDbContext>()
            .Set<Token>().SingleAsync(x => x.Reference == tokenResponse.Response!.AccessToken);

        Assert.NotNull(token.RevokedAt);
    }
}