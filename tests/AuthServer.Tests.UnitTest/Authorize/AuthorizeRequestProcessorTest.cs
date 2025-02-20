using AuthServer.Authorize;
using AuthServer.Constants;
using AuthServer.Core.Abstractions;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Helpers;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;
using ProofKeyForCodeExchangeHelper = AuthServer.Tests.Core.ProofKeyForCodeExchangeHelper;

namespace AuthServer.Tests.UnitTest.Authorize;

public class AuthorizeRequestProcessorTest : BaseUnitTest
{
    public AuthorizeRequestProcessorTest(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task Process_ClientWithoutConsentAndWithRequestUri_ExpectAuthorizationCode()
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var processor = serviceProvider.GetRequiredService<IRequestProcessor<AuthorizeValidatedRequest, string>>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic)
        {
            AuthorizationCodeExpiration = 60,
            RequireConsent = false
        };
        var authorizeMessage = new AuthorizeMessage("value", DateTime.Now.AddSeconds(60), client);
        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, levelOfAssurance);
        await AddEntity(authorizationGrant);
        await AddEntity(authorizeMessage);

        var request = new AuthorizeValidatedRequest
        {
            RequestUri = $"{RequestUriConstants.RequestUriPrefix}{authorizeMessage.Reference}",
            ClientId = client.Id,
            CodeChallenge = ProofKeyForCodeExchangeHelper.GetProofKeyForCodeExchange().CodeChallenge,
            Nonce = CryptographyHelper.GetRandomString(16),
            AuthorizationGrantId = authorizationGrant.Id,
            Scope = [ScopeConstants.OpenId]
        };

        // Act
        var authorizationCode = await processor.Process(request, CancellationToken.None);
        await SaveChangesAsync();

        // Assert
        Assert.NotNull(authorizeMessage.RedeemedAt);
        Assert.NotNull(authorizationCode);
        Assert.Single(authorizationGrant.Nonces);
        Assert.Single(authorizationGrant.AuthorizationCodes);
        Assert.Equal(authorizationCode, authorizationGrant.AuthorizationCodes.Single().Value);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(GrantManagementActionConstants.Create)]
    [InlineData(GrantManagementActionConstants.Replace)]
    [InlineData(GrantManagementActionConstants.Merge)]
    public async Task Process_ClientWithConsent_ExpectAuthorizationCode(string? grantManagementAction)
    {
        // Arrange
        var serviceProvider = BuildServiceProvider();
        var processor = serviceProvider.GetRequiredService<IRequestProcessor<AuthorizeValidatedRequest, string>>();

        var subjectIdentifier = new SubjectIdentifier();
        var session = new Session(subjectIdentifier);
        var client = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic)
        {
            AuthorizationCodeExpiration = 60
        };
        var levelOfAssurance = await GetAuthenticationContextReference(LevelOfAssuranceLow);
        var authorizationGrant = new AuthorizationGrant(session, client, subjectIdentifier.Id, levelOfAssurance);
        await AddEntity(authorizationGrant);

        var openIdScope = await GetScope(ScopeConstants.OpenId);
        var scopeConsent = new ScopeConsent(subjectIdentifier, client, openIdScope);
        await AddEntity(scopeConsent);

        var weatherClient = new Client("web-app", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic)
        {
            ClientUri = "https://weather.authserver.dk"
        };
        weatherClient.Scopes.Add(await GetScope(ScopeConstants.OpenId));
        await AddEntity(weatherClient);

        var request = new AuthorizeValidatedRequest
        {
            ClientId = client.Id,
            CodeChallenge = ProofKeyForCodeExchangeHelper.GetProofKeyForCodeExchange().CodeChallenge,
            Nonce = CryptographyHelper.GetRandomString(16),
            AuthorizationGrantId = authorizationGrant.Id,
            Scope = [ScopeConstants.OpenId],
            Resource = ["https://weather.authserver.dk"],
            GrantManagementAction = grantManagementAction
        };

        // Act
        var authorizationCode = await processor.Process(request, CancellationToken.None);
        await SaveChangesAsync();

        // Assert
        Assert.NotNull(authorizationCode);
        Assert.Single(authorizationGrant.Nonces);
        Assert.Single(authorizationGrant.AuthorizationCodes);
        Assert.Equal(authorizationCode, authorizationGrant.AuthorizationCodes.Single().Value);
        Assert.Single(authorizationGrant.AuthorizationGrantConsents);
    }
}