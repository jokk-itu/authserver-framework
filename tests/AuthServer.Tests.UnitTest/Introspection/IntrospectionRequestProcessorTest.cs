using System.Text.Json;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Extensions;
using AuthServer.Introspection;
using AuthServer.Tests.Core;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Introspection;
public class IntrospectionRequestProcessorTest : BaseUnitTest
{
    public IntrospectionRequestProcessorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task Process_InvalidToken_ExpectActiveIsFalse()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var processor = serviceProvider.GetRequiredService<IRequestProcessor<IntrospectionValidatedRequest, IntrospectionResponse>>();

        var client = new Client("webapp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            ClientUri = "https://webapp.authserver.dk"
        };
        await AddEntity(client);

        var introspectionValidatedRequest = new IntrospectionValidatedRequest
        {
            Token = "invalid_token",
            Scope = [ScopeConstants.OpenId]
        };

        // Act
        var introspectionResponse = await processor.Process(introspectionValidatedRequest, CancellationToken.None);

        // Assert
        Assert.False(introspectionResponse.Active);
    }

    [Fact]
    public async Task Process_ExpiredToken_ExpectActiveIsFalse()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var processor = serviceProvider.GetRequiredService<IRequestProcessor<IntrospectionValidatedRequest, IntrospectionResponse>>();

        var client = new Client("webapp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            ClientUri = "https://webapp.authserver.dk"
        };
        var openIdScope = await IdentityContext.Set<Scope>().SingleAsync(x => x.Name == ScopeConstants.OpenId);
        client.Scopes.Add(openIdScope);
        var token = new ClientAccessToken(client, client.ClientUri, DiscoveryDocument.Issuer, ScopeConstants.OpenId, -1, null);
        
        await AddEntity(token);

        var introspectionValidatedRequest = new IntrospectionValidatedRequest
        {
            Token = token.Reference,
            Scope = [ScopeConstants.OpenId]
        };

        // Act
        var introspectionResponse = await processor.Process(introspectionValidatedRequest, CancellationToken.None);

        // Assert
        Assert.False(introspectionResponse.Active);
    }

    [Fact]
    public async Task Process_RevokedToken_ExpectActiveIsFalse()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var processor = serviceProvider.GetRequiredService<IRequestProcessor<IntrospectionValidatedRequest, IntrospectionResponse>>();

        var client = new Client("webapp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            ClientUri = "https://webapp.authserver.dk"
        };
        var openIdScope = await IdentityContext.Set<Scope>().SingleAsync(x => x.Name == ScopeConstants.OpenId);
        client.Scopes.Add(openIdScope);
        var token = new ClientAccessToken(client, client.ClientUri, DiscoveryDocument.Issuer, ScopeConstants.OpenId, -1, null);
        token.Revoke();
        await AddEntity(token);

        var introspectionValidatedRequest = new IntrospectionValidatedRequest
        {
            Token = token.Reference,
            Scope = [ScopeConstants.OpenId]
        };

        // Act
        var introspectionResponse = await processor.Process(introspectionValidatedRequest, CancellationToken.None);

        // Assert
        Assert.False(introspectionResponse.Active);
    }

    [Fact]
    public async Task Process_InsufficientScopeForClient_ExpectActiveIsFalse()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var processor = serviceProvider.GetRequiredService<IRequestProcessor<IntrospectionValidatedRequest, IntrospectionResponse>>();

        var client = new Client("webapp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            ClientUri = "https://webapp.authserver.dk"
        };
        var token = new ClientAccessToken(client, client.ClientUri, DiscoveryDocument.Issuer, ScopeConstants.OpenId, -1, null);
        await AddEntity(token);

        var introspectionValidatedRequest = new IntrospectionValidatedRequest
        {
            Token = token.Reference,
            Scope = []
        };

        // Act
        var introspectionResponse = await processor.Process(introspectionValidatedRequest, CancellationToken.None);

        // Assert
        Assert.False(introspectionResponse.Active);
    }

    [Fact]
    public async Task Process_ActiveGrantAccessToken_ExpectActive()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var processor = serviceProvider.GetRequiredService<IRequestProcessor<IntrospectionValidatedRequest, IntrospectionResponse>>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);

        var client = new Client("webapp", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            ClientUri = "https://webapp.authserver.dk"
        };
        var openidScope = await IdentityContext.Set<Scope>().SingleAsync(x => x.Name == ScopeConstants.OpenId);
        client.Scopes.Add(openidScope);

        var lowAcr = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, lowAcr);

        var tokenScope = string.Join(' ', [ScopeConstants.OpenId, ScopeConstants.Address]);
        var token = new GrantAccessToken(authorizationGrant, client.ClientUri, DiscoveryDocument.Issuer, tokenScope, 3600, null);
        await AddEntity(token);

        var introspectionValidatedRequest = new IntrospectionValidatedRequest
        {
            Token = token.Reference,
            Scope = [ScopeConstants.OpenId]
        };

        // Act
        var introspectionResponse = await processor.Process(introspectionValidatedRequest, CancellationToken.None);

        // Assert

        Assert.True(introspectionResponse.Active);
        Assert.Equal(token.Id.ToString(), introspectionResponse.JwtId);
        Assert.Equal(client.Id, introspectionResponse.ClientId);
        Assert.Equal(token.ExpiresAt!.Value.ToUnixTimeSeconds(), introspectionResponse.ExpiresAt);
        Assert.Equal(DiscoveryDocument.Issuer, introspectionResponse.Issuer);
        Assert.NotNull(introspectionResponse.Audience);
        Assert.Equal(token.Audience, introspectionResponse.Audience.Single());
        Assert.Equal(token.IssuedAt.ToUnixTimeSeconds(),  introspectionResponse.IssuedAt!.Value);
        Assert.Equal(token.NotBefore.ToUnixTimeSeconds(), introspectionResponse.NotBefore!.Value);
        Assert.Equal(ScopeConstants.OpenId, introspectionResponse.Scope);
        Assert.Equal(subjectIdentifier.Id, introspectionResponse.Subject);
        Assert.Equal(TokenTypeSchemaConstants.Bearer, introspectionResponse.TokenType);
        Assert.Equal(UserConstants.Username, introspectionResponse.Username);
        Assert.Equal(authorizationGrant.UpdatedAuthTime.ToUnixTimeSeconds(), introspectionResponse.AuthTime);
        Assert.Equal(lowAcr.Name, introspectionResponse.Acr);
        Assert.Null(introspectionResponse.Jkt);

        Assert.NotNull(introspectionResponse.AccessControl);
        Assert.Equal(UserConstants.Roles, JsonSerializer.Deserialize<IEnumerable<string>>(introspectionResponse.AccessControl[ClaimNameConstants.Roles].ToString()!));
    }

    [Fact]
    public async Task Process_ActiveClientAccessToken_ExpectActive()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var processor = serviceProvider.GetRequiredService<IRequestProcessor<IntrospectionValidatedRequest, IntrospectionResponse>>();

        var weatherClient = new Client("weather-api", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            ClientUri = "https://weather.authserver.dk"
        };
        var weatherReadScope = new Scope("weather:read");
        weatherClient.Scopes.Add(weatherReadScope);
        await AddEntity(weatherClient);

        var client = new Client("worker-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        client.Scopes.Add(weatherReadScope);

        var token = new ClientAccessToken(client, weatherClient.ClientUri!, DiscoveryDocument.Issuer, weatherReadScope.Name, 3600, "jkt");
        await AddEntity(token);

        var introspectionValidatedRequest = new IntrospectionValidatedRequest
        {
            Token = token.Reference,
            Scope = [weatherReadScope.Name]
        };

        // Act
        var introspectionResponse = await processor.Process(introspectionValidatedRequest, CancellationToken.None);

        // Assert
        Assert.True(introspectionResponse.Active);
        Assert.Equal(token.Id.ToString(), introspectionResponse.JwtId);
        Assert.Equal(client.Id, introspectionResponse.ClientId);
        Assert.Equal(token.ExpiresAt!.Value.ToUnixTimeSeconds(), introspectionResponse.ExpiresAt);
        Assert.Equal(DiscoveryDocument.Issuer, introspectionResponse.Issuer);
        Assert.NotNull(introspectionResponse.Audience);
        Assert.Equal(token.Audience, introspectionResponse.Audience.Single());
        Assert.Equal(token.IssuedAt.ToUnixTimeSeconds(), introspectionResponse.IssuedAt!.Value);
        Assert.Equal(token.NotBefore.ToUnixTimeSeconds(), introspectionResponse.NotBefore!.Value);
        Assert.Equal(weatherReadScope.Name, introspectionResponse.Scope);
        Assert.Equal(client.Id, introspectionResponse.Subject);
        Assert.Equal(TokenTypeSchemaConstants.DPoP, introspectionResponse.TokenType);
        Assert.Null(introspectionResponse.Username);
        Assert.Null(introspectionResponse.AuthTime);
        Assert.Null(introspectionResponse.Acr);
        Assert.Null(introspectionResponse.AccessControl);
        Assert.Equal(token.Jkt, introspectionResponse.Jkt);
    }
}
