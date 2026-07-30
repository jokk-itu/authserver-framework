using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Constants;
using AuthServer.Entities;
using AuthServer.Enums;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.Authorization;

public class TokenAuthorizationValidatorTest : BaseUnitTest
{
    public TokenAuthorizationValidatorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task ValidateTokenAuthorizationGrant_NoConsent_ExpectConsentNotFound()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var service = serviceProvider.GetRequiredService<ITokenAuthorizationValidatorService>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationCodeGrant = new AuthorizationCodeGrant(session, client, subjectIdentifier.Id, levelOfAssurance);
        await AddEntity(authorizationCodeGrant);

        // Act
        var result = await service.ValidateTokenAuthorizationGrant(new TokenAuthorizationGrantValidationDto
        {
            Scopes = [],
            Resources = [],
            AuthorizationDetails = [],
            AuthorizationGrantId = authorizationCodeGrant.Id
        }, CancellationToken.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Empty(result.Resources);
        Assert.Empty(result.Scopes);
        Assert.Equal(TokenAuthorizationValidationError.ConsentNotFound, result.Error);
    }

    [Fact]
    public async Task ValidateTokenAuthorizationGrant_RequestedScopesExceedsConsent_ExpectScopeExceedsConsent()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var service = serviceProvider.GetRequiredService<ITokenAuthorizationValidatorService>();

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
        var result = await service.ValidateTokenAuthorizationGrant(new TokenAuthorizationGrantValidationDto
        {
            Scopes = [ScopeConstants.UserInfo],
            Resources = [],
            AuthorizationDetails = [],
            AuthorizationGrantId = authorizationCodeGrant.Id
        }, CancellationToken.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Empty(result.Resources);
        Assert.Empty(result.Scopes);
        Assert.Equal(TokenAuthorizationValidationError.ScopeExceedsConsent, result.Error);
    }

    [Fact]
    public async Task ValidateTokenAuthorizationGrant_RequestedResourcesExceedsConsent_ExpectResourceExceedsConsent()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var service = serviceProvider.GetRequiredService<ITokenAuthorizationValidatorService>();

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
        var result = await service.ValidateTokenAuthorizationGrant(new TokenAuthorizationGrantValidationDto
        {
            Scopes = [],
            Resources = ["resource2"],
            AuthorizationDetails = [],
            AuthorizationGrantId = authorizationCodeGrant.Id
        }, CancellationToken.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Empty(result.Resources);
        Assert.Empty(result.Scopes);
        Assert.Equal(TokenAuthorizationValidationError.ResourceExceedsConsent, result.Error);
    }

    [Fact]
    public async Task ValidateTokenAuthorizationGrant_ResourcesAreNotAuthorizedForScope_ExpectUnauthorizedResourceForScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var service = serviceProvider.GetRequiredService<ITokenAuthorizationValidatorService>();

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
        var result = await service.ValidateTokenAuthorizationGrant(new TokenAuthorizationGrantValidationDto
        {
            Scopes = [],
            Resources = [],
            AuthorizationDetails = [],
            AuthorizationGrantId = authorizationCodeGrant.Id
        }, CancellationToken.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Empty(result.Resources);
        Assert.Empty(result.Scopes);
        Assert.Equal(TokenAuthorizationValidationError.UnauthorizedResourceForScope, result.Error);
    }

    [Theory]
    [InlineData(ScopeConstants.OpenId, null)]
    [InlineData(null, "https://api.authserver.dk")]
    [InlineData(ScopeConstants.OpenId, "https://api.authserver.dk")]
    public async Task ValidateTokenAuthorizationGrant_ScopesAndResources_ExpectValidScopeResourceValidationResult(string? scope, string? resource)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var service = serviceProvider.GetRequiredService<ITokenAuthorizationValidatorService>();

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
        var result = await service.ValidateTokenAuthorizationGrant(new TokenAuthorizationGrantValidationDto
        {
            Scopes = scopes,
            Resources = resources,
            AuthorizationDetails = [],
            AuthorizationGrantId = authorizationCodeGrant.Id
        }, CancellationToken.None);

        // Assert
        Assert.True(result.IsValid);
        Assert.Equal([resourceClient.ClientUri!], result.Resources);
        Assert.Equal([openIdScope.Name], result.Scopes);
        Assert.Null(result.Error);
    }

    [Fact]
    public async Task ValidateTokenAuthorizationClient_ClientIsNotAuthorizedForScopes_ExpectUnauthorizedClientForScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var service = serviceProvider.GetRequiredService<ITokenAuthorizationValidatorService>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        await AddEntity(client);

        // Act
        var result = await service.ValidateTokenAuthorizationClient(new TokenAuthorizationClientValidationDto
        {
            Scopes = [ScopeConstants.OpenId],
            Resources = [],
            AuthorizationDetails = [],
            ClientId = client.Id
        }, CancellationToken.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Empty(result.Resources);
        Assert.Empty(result.Scopes);
        Assert.Equal(TokenAuthorizationValidationError.UnauthorizedClientForScope, result.Error);
    }

    [Fact]
    public async Task ValidateTokenAuthorizationClient_ResourcesEmpty_ExpectArgumentException()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var service = serviceProvider.GetRequiredService<ITokenAuthorizationValidatorService>();

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        client.Scopes.Add(await GetScope(ScopeConstants.OpenId));
        await AddEntity(client);

        // Act and Assert
        await Assert.ThrowsAsync<ArgumentException>(() => service.ValidateTokenAuthorizationClient(new TokenAuthorizationClientValidationDto
        {
            Scopes = [],
            Resources = [],
            AuthorizationDetails = [],
            ClientId = client.Id
        }, CancellationToken.None));
    }

    [Fact]
    public async Task ValidateTokenAuthorizationClient_ResourceIsNotAuthorizedForScopes_ExpectUnauthorizedResourceForScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var service = serviceProvider.GetRequiredService<ITokenAuthorizationValidatorService>();

        var resourceClient = new Client("api", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            ClientUri = "https://api.authserver.dk"
        };
        await AddEntity(resourceClient);

        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        client.Scopes.Add(await GetScope(ScopeConstants.OpenId));
        await AddEntity(client);

        // Act
        var result = await service.ValidateTokenAuthorizationClient(new TokenAuthorizationClientValidationDto
        {
            Scopes = [],
            Resources = [resourceClient.ClientUri!],
            AuthorizationDetails = [],
            ClientId = client.Id
        }, CancellationToken.None);

        // Assert
        Assert.False(result.IsValid);
        Assert.Empty(result.Resources);
        Assert.Empty(result.Scopes);
        Assert.Equal(TokenAuthorizationValidationError.UnauthorizedResourceForScope, result.Error);
    }

    [Theory]
    [InlineData(null, "https://api.authserver.dk")]
    [InlineData(ScopeConstants.OpenId, "https://api.authserver.dk")]
    public async Task ValidateTokenAuthorizationClient_ScopeAndResource_ExpectValidScopeResourceValidationResult(string? scope, string? resource)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var service = serviceProvider.GetRequiredService<ITokenAuthorizationValidatorService>();

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
        var result = await service.ValidateTokenAuthorizationClient(new TokenAuthorizationClientValidationDto
        {
            Scopes = scopes,
            Resources = resources,
            AuthorizationDetails = [],
            ClientId = client.Id
        }, CancellationToken.None);

        // Assert
        Assert.True(result.IsValid);
        Assert.Equal([resourceClient.ClientUri!], result.Resources);
        Assert.Equal([openIdScope.Name], result.Scopes);
        Assert.Null(result.Error);
    }
}