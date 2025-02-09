using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.GrantManagement;
using AuthServer.RequestAccessors.GrantManagement;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest.GrantManagement;

public class GrantManagementRequestValidatorTest : BaseUnitTest
{
    public GrantManagementRequestValidatorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task Validate_NullGrantId_ExpectInvalidGrantId()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<GrantManagementRequest, GrantManagementValidatedRequest>>();

        var request = new GrantManagementRequest
        {
            Method = HttpMethod.Delete,
            AccessToken = "token"
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.False(processResult.IsSuccess);
        Assert.Equal(GrantManagementError.InvalidGrantId, processResult.Error);
    }

    [Fact]
    public async Task Validate_InvalidGrantId_ExpectUnexistingGrantId()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<GrantManagementRequest, GrantManagementValidatedRequest>>();

        var request = new GrantManagementRequest
        {
            Method = HttpMethod.Delete,
            AccessToken = "token",
            GrantId = Guid.NewGuid().ToString()
        };

        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);

        // Assert
        Assert.False(processResult.IsSuccess);
        Assert.Equal(GrantManagementError.NotFoundGrantId, processResult.Error);
    }

    [Fact]
    public async Task Validate_JwtAccessTokenWithMismatchingClientId_ExpectInvalidGrant()
    {
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<GrantManagementRequest, GrantManagementValidatedRequest>>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var authenticationContextReference = await GetAuthenticationContextReference(LevelOfAssuranceStrict);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, authenticationContextReference);
        await AddEntity(authorizationGrant);

        var accessToken = JwtBuilder.GetAccessToken("other_client_id");

        var request = new GrantManagementRequest
        {
            Method = HttpMethod.Delete,
            AccessToken = accessToken,
            GrantId = authorizationGrant.Id
        };
        
        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);
        
        // Assert
        Assert.False(processResult.IsSuccess);
        Assert.Equal(GrantManagementError.InvalidGrant, processResult.Error);
    }

    [Fact]
    public async Task Validate_ReferenceAccessTokenWithMismatchingClientId_ExpectInvalidGrant()
    {
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<GrantManagementRequest, GrantManagementValidatedRequest>>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var authenticationContextReference = await GetAuthenticationContextReference(LevelOfAssuranceStrict);
        
        var clientOne = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var authorizationGrantOne = new AuthorizationGrant(session, clientOne, subjectIdentifier.Id, authenticationContextReference);
        await AddEntity(authorizationGrantOne);
        
        var clientTwo = new Client("mobile-app", ApplicationType.Native, TokenEndpointAuthMethod.None);
        var authorizationGrantTwo = new AuthorizationGrant(session, clientTwo, subjectIdentifier.Id, authenticationContextReference);
        var accessToken = new GrantAccessToken(authorizationGrantTwo, "aud", "iss", "scope", 3600);
        await AddEntity(accessToken);

        var request = new GrantManagementRequest
        {
            Method = HttpMethod.Delete,
            AccessToken = accessToken.Reference,
            GrantId = authorizationGrantOne.Id
        };
        
        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);
        
        // Assert
        Assert.False(processResult.IsSuccess);
        Assert.Equal(GrantManagementError.InvalidGrant, processResult.Error);
    }

    [Fact]
    public async Task Validate_JwtAccessToken_ExpectValidRequest()
    {
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<GrantManagementRequest, GrantManagementValidatedRequest>>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var authenticationContextReference = await GetAuthenticationContextReference(LevelOfAssuranceStrict);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, authenticationContextReference);
        await AddEntity(authorizationGrant);

        var accessToken = JwtBuilder.GetAccessToken(client.Id);

        var request = new GrantManagementRequest
        {
            Method = HttpMethod.Delete,
            AccessToken = accessToken,
            GrantId = authorizationGrant.Id
        };
        
        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);
        
        // Assert
        Assert.True(processResult.IsSuccess);
        Assert.Equal(authorizationGrant.Id, processResult.Value!.GrantId);
    }

    [Fact]
    public async Task Validate_ReferenceAccessToken_ExpectValidRequest()
    {
        var serviceProvider = BuildServiceProvider();
        var validator = serviceProvider
            .GetRequiredService<IRequestValidator<GrantManagementRequest, GrantManagementValidatedRequest>>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var authenticationContextReference = await GetAuthenticationContextReference(LevelOfAssuranceStrict);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, authenticationContextReference);
        var accessToken = new GrantAccessToken(authorizationGrant, "aud", "iss", "scope", 3600);
        await AddEntity(accessToken);

        var request = new GrantManagementRequest
        {
            Method = HttpMethod.Delete,
            AccessToken = accessToken.Reference,
            GrantId = authorizationGrant.Id
        };
        
        // Act
        var processResult = await validator.Validate(request, CancellationToken.None);
        
        // Assert
        Assert.True(processResult.IsSuccess);
        Assert.Equal(authorizationGrant.Id, processResult.Value!.GrantId);
    }
}