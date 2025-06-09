using AuthServer.Authentication.Models;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.Models;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Helpers;
using AuthServer.Tests.Core;
using AuthServer.TokenByGrant;
using AuthServer.TokenByGrant.ClientCredentialsGrant;
using AuthServer.TokenByGrant.RefreshTokenGrant;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.TokenByGrant.ClientCredentialsGrant;

public class ClientCredentialsRequestValidatorTest : BaseUnitTest
{
    public ClientCredentialsRequestValidatorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task Validate_EmptyGrantType_ExpectUnsupportedGrantType()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<IRequestValidator<TokenRequest, ClientCredentialsValidatedRequest>>();

        var request = new TokenRequest();
        
        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.UnsupportedGrantType, processResult);
    }

    [Fact]
    public async Task Validate_EmptyScope_ExpectInvalidScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<IRequestValidator<TokenRequest, ClientCredentialsValidatedRequest>>();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.ClientCredentials
        };
        
        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidScope, processResult);
    }

    [Fact]
    public async Task Validate_EmptyResource_ExpectInvalidResource()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<IRequestValidator<TokenRequest, ClientCredentialsValidatedRequest>>();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.ClientCredentials,
            Scope = [ScopeConstants.OpenId]
        };
        
        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidResource, processResult);
    }

    [Fact]
    public async Task Validate_NoClientAuthentication_ExpectMultipleOrNoneClientMethod()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<IRequestValidator<TokenRequest, ClientCredentialsValidatedRequest>>();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.ClientCredentials,
            Scope = [ScopeConstants.OpenId],
            Resource = ["resource"]
        };
        
        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.MultipleOrNoneClientMethod, processResult);
    }

    [Fact]
    public async Task Validate_InvalidClientAuthentication_ExpectInvalidClient()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<IRequestValidator<TokenRequest, ClientCredentialsValidatedRequest>>();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.ClientCredentials,
            Scope = [ScopeConstants.OpenId],
            Resource = ["resource"],
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    "clientId",
                    "clientSecret")
            ]
        };
        
        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidClient, processResult);
    }

    [Fact]
    public async Task Validate_UnauthorizedForClientCredentials_ExpectUnauthorizedForGrantType()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<IRequestValidator<TokenRequest, ClientCredentialsValidatedRequest>>();

        var client = new Client("worker-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var plainSecret = CryptographyHelper.GetRandomString(32);
        var hashedSecret = CryptographyHelper.HashPassword(plainSecret);
        client.SetSecret(hashedSecret);
        await AddEntity(client);

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.ClientCredentials,
            Scope = [ScopeConstants.OpenId],
            Resource = ["resource"],
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };
        
        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.UnauthorizedForGrantType, processResult);
    }

    [Fact]
    public async Task Validate_RequireDPoPWithoutDPoPProof_ExpectDPoPRequired()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, ClientCredentialsValidatedRequest>>();

        var client = new Client("worker-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            RequireDPoPBoundAccessTokens = true
        };
        var plainSecret = CryptographyHelper.GetRandomString(32);
        var hashedSecret = CryptographyHelper.HashPassword(plainSecret);
        client.SetSecret(hashedSecret);
        var clientCredentialsGrant = await GetGrantType(GrantTypeConstants.ClientCredentials);
        client.GrantTypes.Add(clientCredentialsGrant);
        await AddEntity(client);

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.ClientCredentials,
            Scope = [ScopeConstants.OpenId],
            Resource = ["resource"],
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.DPoPRequired, processResult);
    }

    [Fact]
    public async Task Validate_InvalidDPoP_ExpectInvalidDPoP()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, ClientCredentialsValidatedRequest>>();

        var client = new Client("worker-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var plainSecret = CryptographyHelper.GetRandomString(32);
        var hashedSecret = CryptographyHelper.HashPassword(plainSecret);
        client.SetSecret(hashedSecret);
        var clientCredentialsGrant = await GetGrantType(GrantTypeConstants.ClientCredentials);
        client.GrantTypes.Add(clientCredentialsGrant);
        await AddEntity(client);

        const string dPoP = "invalid_dpop_proof";
        dPoPService
            .Setup(x => x.ValidateDPoP(dPoP, client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = false
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.ClientCredentials,
            Scope = [ScopeConstants.OpenId],
            Resource = ["resource"],
            DPoP = dPoP,
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidDPoP, processResult);
        dPoPService.Verify();
    }

    [Fact]
    public async Task Validate_DPoPWithoutNonceClaim_ExpectUseDPoPNonce()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });

        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<TokenRequest, ClientCredentialsValidatedRequest>>();

        var client = new Client("worker-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var plainSecret = CryptographyHelper.GetRandomString(32);
        var hashedSecret = CryptographyHelper.HashPassword(plainSecret);
        client.SetSecret(hashedSecret);
        var clientCredentialsGrant = await GetGrantType(GrantTypeConstants.ClientCredentials);
        client.GrantTypes.Add(clientCredentialsGrant);
        await AddEntity(client);

        const string dPoP = "invalid_dpop_proof";
        const string dPoPNonce = "dpop_nonce";
        dPoPService
            .Setup(x => x.ValidateDPoP(dPoP, client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = false,
                DPoPNonce = dPoPNonce
            })
            .Verifiable();

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.ClientCredentials,
            Scope = [ScopeConstants.OpenId],
            Resource = ["resource"],
            DPoP = dPoP,
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.UseDPoPNonce(dPoPNonce), processResult);
        dPoPService.Verify();
    }

    [Fact]
    public async Task Validate_UnauthorizedScope_ExpectUnauthorizedForScope()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<IRequestValidator<TokenRequest, ClientCredentialsValidatedRequest>>();

        var client = new Client("worker-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var plainSecret = CryptographyHelper.GetRandomString(32);
        var hashedSecret = CryptographyHelper.HashPassword(plainSecret);
        client.SetSecret(hashedSecret);
        var clientCredentialsGrant = await GetGrantType(GrantTypeConstants.ClientCredentials);
        client.GrantTypes.Add(clientCredentialsGrant);
        await AddEntity(client);

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.ClientCredentials,
            Scope = [ScopeConstants.OpenId],
            Resource = ["resource"],
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };
        
        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.UnauthorizedForScope, processResult);
    }

    [Fact]
    public async Task Validate_ResourceDoesNotExist_ExpectInvalidResource()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider.GetRequiredService<IRequestValidator<TokenRequest, ClientCredentialsValidatedRequest>>();

        var client = new Client("worker-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var plainSecret = CryptographyHelper.GetRandomString(32);
        var hashedSecret = CryptographyHelper.HashPassword(plainSecret);
        client.SetSecret(hashedSecret);

        var clientCredentialsGrant = await GetGrantType(GrantTypeConstants.ClientCredentials);
        client.GrantTypes.Add(clientCredentialsGrant);

        var scope = await GetScope(ScopeConstants.OpenId);
        client.Scopes.Add(scope);

        await AddEntity(client);

        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.ClientCredentials,
            Scope = [ScopeConstants.OpenId],
            Resource = ["resource"],
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };
        
        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(TokenError.InvalidResource, processResult);
    }

    [Fact]
    public async Task Validate_ValidatedRequest_ExpectValidatedRequest()
    {
        // Arrange
        var dPoPService = new Mock<IDPoPService>();
        var serviceProvider = BuildServiceProvider(services =>
        {
            services.AddScopedMock(dPoPService);
        });
        var validator = serviceProvider.GetRequiredService<IRequestValidator<TokenRequest, ClientCredentialsValidatedRequest>>();

        var client = new Client("worker-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60);
        var plainSecret = CryptographyHelper.GetRandomString(32);
        var hashedSecret = CryptographyHelper.HashPassword(plainSecret);
        client.SetSecret(hashedSecret);

        var clientCredentialsGrant = await GetGrantType(GrantTypeConstants.ClientCredentials);
        client.GrantTypes.Add(clientCredentialsGrant);

        var openIdScope = await GetScope(ScopeConstants.OpenId);
        client.Scopes.Add(openIdScope);

        await AddEntity(client);

        var weatherClient = new Client("weather-api", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic, 300, 60)
        {
            ClientUri = "https://weather.authserver.dk"
        };
        weatherClient.Scopes.Add(openIdScope);
        await AddEntity(weatherClient);

        const string dPoP = "dpop";
        const string dPoPJkt = "dpop_jkt";
        dPoPService
            .Setup(x => x.ValidateDPoP(dPoP, client.Id, It.IsAny<CancellationToken>()))
            .ReturnsAsync(new DPoPValidationResult
            {
                IsValid = true,
                DPoPJkt = dPoPJkt
            })
            .Verifiable();

        var scope = new[] { ScopeConstants.OpenId };
        var resource = new[] { weatherClient.ClientUri };
        var request = new TokenRequest
        {
            GrantType = GrantTypeConstants.ClientCredentials,
            Scope = scope,
            Resource = resource,
            DPoP = dPoP,
            ClientAuthentications = [
                new ClientSecretAuthentication(
                    TokenEndpointAuthMethod.ClientSecretBasic,
                    client.Id,
                    plainSecret)
            ]
        };
        
        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.Equal(client.Id, processResult.Value!.ClientId);
        Assert.Equal(scope, processResult.Value!.Scope);
        Assert.Equal(resource, processResult.Value!.Resource);
        dPoPService.Verify();
    }
}