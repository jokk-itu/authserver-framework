using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Constants;
using AuthServer.Entities;
using AuthServer.Enums;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Authorization;

public class ScopeResourceServiceTest : BaseUnitTest
{
    public ScopeResourceServiceTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task ValidateScopeResourceForGrant_NoConsent_ExpectConsentNotFound()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var service = serviceProvider.GetRequiredService<IScopeResourceService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationCodeGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);
        await AddEntity(authorizationCodeGrant);

        // Act
        var result = await service.ValidateScopeResourceForGrant([], [], authorizationCodeGrant.Id, CancellationToken.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Empty(result.Resources);
        Assert.Empty(result.Scopes);
        Assert.Equal(ScopeResourceError.ConsentNotFound, result.Error);
    }

    [Fact]
    public async Task ValidateScopeResourceForGrant_RequestedScopesExceedsConsent_ExpectScopeExceedsConsent()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var service = serviceProvider.GetRequiredService<IScopeResourceService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);

        var scopeConsent = new ScopeConsent(subjectIdentifier, client, await GetScope(ScopeConstants.OpenId));
        await AddEntity(scopeConsent);

        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationCodeGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);
        var grantScopeConsent = new AuthorizationGrantScopeConsent(scopeConsent, authorizationCodeGrant, "resource");
        await AddEntity(grantScopeConsent);

        // Act
        var result = await service.ValidateScopeResourceForGrant([ScopeConstants.UserInfo], [], authorizationCodeGrant.Id, CancellationToken.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Empty(result.Resources);
        Assert.Empty(result.Scopes);
        Assert.Equal(ScopeResourceError.ScopeExceedsConsent, result.Error);
    }

    [Fact]
    public async Task ValidateScopeResourceForGrant_RequestedResourcesExceedsConsent_ExpectResourceExceedsConsent()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var service = serviceProvider.GetRequiredService<IScopeResourceService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);

        var scopeConsent = new ScopeConsent(subjectIdentifier, client, await GetScope(ScopeConstants.OpenId));
        await AddEntity(scopeConsent);

        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationCodeGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);
        var grantScopeConsent = new AuthorizationGrantScopeConsent(scopeConsent, authorizationCodeGrant, "resource");
        await AddEntity(grantScopeConsent);

        // Act
        var result = await service.ValidateScopeResourceForGrant([], ["resource2"], authorizationCodeGrant.Id, CancellationToken.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Empty(result.Resources);
        Assert.Empty(result.Scopes);
        Assert.Equal(ScopeResourceError.ResourceExceedsConsent, result.Error);
    }

    [Fact]
    public async Task ValidateScopeResourceForGrant_ResourcesAreNotAuthorizedForScope_ExpectUnauthorizedResourceForScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var service = serviceProvider.GetRequiredService<IScopeResourceService>();

        var resourceClient = new Client("api", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            ClientUri = "https://api.authserver.dk"
        };
        await AddEntity(resourceClient);

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);

        var scopeConsent = new ScopeConsent(subjectIdentifier, client, await GetScope(ScopeConstants.OpenId));
        await AddEntity(scopeConsent);

        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationCodeGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);
        var grantScopeConsent = new AuthorizationGrantScopeConsent(scopeConsent, authorizationCodeGrant, resourceClient.ClientUri!);
        await AddEntity(grantScopeConsent);

        // Act
        var result = await service.ValidateScopeResourceForGrant([], [], authorizationCodeGrant.Id, CancellationToken.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Empty(result.Resources);
        Assert.Empty(result.Scopes);
        Assert.Equal(ScopeResourceError.UnauthorizedResourceForScope, result.Error);
    }

    [Theory]
    [InlineData(ScopeConstants.OpenId, null)]
    [InlineData(null, "https://api.authserver.dk")]
    [InlineData(ScopeConstants.OpenId, "https://api.authserver.dk")]
    public async Task ValidateScopeResourceForGrant_ScopesAndResources_ExpectValidScopeResourceValidationResult(string? scope, string? resource)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var service = serviceProvider.GetRequiredService<IScopeResourceService>();

        List<string> scopes = scope is null ? [] : [scope];
        List<string> resources = resource is null ? [] : [resource];

        var openIdScope = await GetScope(ScopeConstants.OpenId);
        var resourceClient = new Client("api", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            ClientUri = "https://api.authserver.dk"
        };
        resourceClient.Scopes.Add(openIdScope);
        await AddEntity(resourceClient);

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);

        var scopeConsent = new ScopeConsent(subjectIdentifier, client, openIdScope);
        await AddEntity(scopeConsent);

        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationCodeGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);
        var grantScopeConsent = new AuthorizationGrantScopeConsent(scopeConsent, authorizationCodeGrant, resourceClient.ClientUri!);
        await AddEntity(grantScopeConsent);

        // Act
        var result = await service.ValidateScopeResourceForGrant(scopes, resources, authorizationCodeGrant.Id, CancellationToken.None);

        // Assert
        Assert.True(result.IsValid);
        Assert.Equal([resourceClient.ClientUri!], result.Resources);
        Assert.Equal([openIdScope.Name], result.Scopes);
        Assert.Null(result.Error);
    }

    [Fact]
    public async Task ValidateScopeResourceForClient_ClientIsNotAuthorizedForScopes_ExpectUnauthorizedClientForScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var service = serviceProvider.GetRequiredService<IScopeResourceService>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);

        // Act
        var result = await service.ValidateScopeResourceForClient([ScopeConstants.OpenId], [], client.Id, CancellationToken.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Empty(result.Resources);
        Assert.Empty(result.Scopes);
        Assert.Equal(ScopeResourceError.UnauthorizedClientForScope, result.Error);
    }

    [Fact]
    public async Task ValidateScopeResourceForClient_ResourcesEmpty_ExpectArgumentException()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var service = serviceProvider.GetRequiredService<IScopeResourceService>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        client.Scopes.Add(await GetScope(ScopeConstants.OpenId));
        await AddEntity(client);

        // Act and Assert
        await Assert.ThrowsAsync<ArgumentException>(() => service.ValidateScopeResourceForClient([], [], client.Id, CancellationToken.None));
    }

    [Fact]
    public async Task ValidateScopeResourceForClient_ResourceIsNotAuthorizedForScopes_ExpectUnauthorizedResourceForScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var service = serviceProvider.GetRequiredService<IScopeResourceService>();

        var resourceClient = new Client("api", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            ClientUri = "https://api.authserver.dk"
        };
        await AddEntity(resourceClient);

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        client.Scopes.Add(await GetScope(ScopeConstants.OpenId));
        await AddEntity(client);

        // Act
        var result = await service.ValidateScopeResourceForClient([], [resourceClient.ClientUri!], client.Id, CancellationToken.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Empty(result.Resources);
        Assert.Empty(result.Scopes);
        Assert.Equal(ScopeResourceError.UnauthorizedResourceForScope, result.Error);
    }

    [Theory]
    [InlineData(null, "https://api.authserver.dk")]
    [InlineData(ScopeConstants.OpenId, "https://api.authserver.dk")]
    public async Task ValidateScopeResourceForClient_ScopeAndResource_ExpectValidScopeResourceValidationResult(string? scope, string? resource)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var service = serviceProvider.GetRequiredService<IScopeResourceService>();

        List<string> scopes = scope is null ? [] : [scope];
        List<string> resources = resource is null ? [] : [resource];

        var openIdScope = await GetScope(ScopeConstants.OpenId);

        var resourceClient = new Client("api", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            ClientUri = "https://api.authserver.dk"
        };
        resourceClient.Scopes.Add(openIdScope);
        await AddEntity(resourceClient);

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        client.Scopes.Add(openIdScope);
        await AddEntity(client);

        // Act
        var result = await service.ValidateScopeResourceForClient(scopes, resources, client.Id, CancellationToken.None);

        // Assert
        Assert.True(result.IsValid);
        Assert.Equal([resourceClient.ClientUri!], result.Resources);
        Assert.Equal([openIdScope.Name], result.Scopes);
        Assert.Null(result.Error);
    }
}