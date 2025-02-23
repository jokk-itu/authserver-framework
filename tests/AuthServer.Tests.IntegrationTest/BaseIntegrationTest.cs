using AuthServer.Authentication.Abstractions;
using AuthServer.Authorize.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Helpers;
using AuthServer.Options;
using AuthServer.Repositories.Abstractions;
using AuthServer.Tests.Core;
using AuthServer.Tests.IntegrationTest.EndpointBuilders;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Xunit.Abstractions;

namespace AuthServer.Tests.IntegrationTest;

[Collection("IntegrationTest")]
public abstract class BaseIntegrationTest : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    protected readonly ITestOutputHelper TestOutputHelper;
    protected readonly IServiceProvider ServiceProvider;
    protected readonly AuthorizeEndpointBuilder AuthorizeEndpointBuilder;
    protected readonly RegisterEndpointBuilder RegisterEndpointBuilder;
    protected readonly IntrospectionEndpointBuilder IntrospectionEndpointBuilder;
    protected readonly RevocationEndpointBuilder RevocationEndpointBuilder;
    protected readonly UserinfoEndpointBuilder UserinfoEndpointBuilder;
    protected readonly PushedAuthorizationEndpointBuilder PushedAuthorizationEndpointBuilder;
    protected readonly GrantManagementEndpointBuilder GrantManagementEndpointBuilder;

    protected TokenEndpointBuilder TokenEndpointBuilder => new(GetHttpClient(), DiscoveryDocument, JwksDocument, TestOutputHelper);

    private readonly IOptionsMonitor<DiscoveryDocument> _discoveryDocumentOptions;
    protected DiscoveryDocument DiscoveryDocument => _discoveryDocumentOptions.CurrentValue;

    private readonly IOptionsMonitor<UserInteraction> _userInteractionOptions;
    protected UserInteraction UserInteraction => _userInteractionOptions.CurrentValue;

    private readonly IOptionsMonitor<JwksDocument> _jwksDocumentOptions;
    protected JwksDocument JwksDocument => _jwksDocumentOptions.CurrentValue;

    protected JwtBuilder JwtBuilder => new (DiscoveryDocument, JwksDocument);

    protected const string LevelOfAssuranceLow = AuthenticationContextReferenceConstants.LevelOfAssuranceLow;
    protected const string LevelOfAssuranceSubstantial = AuthenticationContextReferenceConstants.LevelOfAssuranceSubstantial;
    protected const string LevelOfAssuranceStrict = AuthenticationContextReferenceConstants.LevelOfAssuranceStrict;

    protected BaseIntegrationTest(WebApplicationFactory<Program> factory, ITestOutputHelper testOutputHelper)
    {
        _factory = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Integration");
            builder.ConfigureServices(services =>
            {
                var authenticatedUserAccessor = new Mock<IAuthenticatedUserAccessor>();
                authenticatedUserAccessor
                    .Setup(x => x.CountAuthenticatedUsers())
                    .ReturnsAsync(2);

                services.AddScopedMock(authenticatedUserAccessor);
            });
        });

        TestOutputHelper = testOutputHelper;
        ServiceProvider = _factory.Services.CreateScope().ServiceProvider;

        _discoveryDocumentOptions = _factory.Services.GetRequiredService<IOptionsMonitor<DiscoveryDocument>>();
        _userInteractionOptions = _factory.Services.GetRequiredService<IOptionsMonitor<UserInteraction>>();
        _jwksDocumentOptions = _factory.Services.GetRequiredService<IOptionsMonitor<JwksDocument>>();

        ServiceProvider.GetRequiredService<AuthorizationDbContext>().Database.EnsureDeleted();
        ServiceProvider.GetRequiredService<AuthorizationDbContext>().Database.Migrate();

        var dataProtectionProvider = ServiceProvider.GetRequiredService<IDataProtectionProvider>();
        AuthorizeEndpointBuilder = new AuthorizeEndpointBuilder(
            GetHttpClient(),
            dataProtectionProvider,
            DiscoveryDocument,
            JwksDocument,
            TestOutputHelper);

        RegisterEndpointBuilder = new RegisterEndpointBuilder(
            GetHttpClient(),
            DiscoveryDocument,
            JwksDocument,
            TestOutputHelper);

        IntrospectionEndpointBuilder = new IntrospectionEndpointBuilder(
            GetHttpClient(),
            DiscoveryDocument,
            JwksDocument,
            TestOutputHelper);

        RevocationEndpointBuilder = new RevocationEndpointBuilder(
            GetHttpClient(),
            DiscoveryDocument,
            JwksDocument,
            TestOutputHelper);

        UserinfoEndpointBuilder = new UserinfoEndpointBuilder(
            GetHttpClient(),
            DiscoveryDocument,
            JwksDocument,
            TestOutputHelper);

        PushedAuthorizationEndpointBuilder = new PushedAuthorizationEndpointBuilder(
            GetHttpClient(),
            DiscoveryDocument,
            JwksDocument,
            TestOutputHelper);

        GrantManagementEndpointBuilder = new GrantManagementEndpointBuilder(
            GetHttpClient(),
            DiscoveryDocument,
            JwksDocument,
            TestOutputHelper);
    }

    protected HttpClient GetHttpClient() => _factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false
    });

    protected async Task<string> CreateAuthorizationGrant(string clientId, IReadOnlyCollection<string> amr)
    {
        var authenticationContextResolver = ServiceProvider.GetRequiredService<IAuthenticationContextReferenceResolver>();
        var acr = await authenticationContextResolver.ResolveAuthenticationContextReference(amr, CancellationToken.None);

        var authorizationGrantRepository = ServiceProvider.GetRequiredService<IAuthorizationGrantRepository>();
        var grant = await authorizationGrantRepository.CreateAuthorizationGrant(
            UserConstants.SubjectIdentifier,
            clientId,
            acr,
            amr,
            CancellationToken.None);

        return grant.Id;
    }

    protected async Task UpdateAuthorizationGrant(string authorizationGrantId, IReadOnlyCollection<string> amr)
    {
        var authenticationContextResolver = ServiceProvider.GetRequiredService<IAuthenticationContextReferenceResolver>();
        var acr = await authenticationContextResolver.ResolveAuthenticationContextReference(amr, CancellationToken.None);

        var authorizationGrantRepository = ServiceProvider.GetRequiredService<IAuthorizationGrantRepository>();
        await authorizationGrantRepository.UpdateAuthorizationGrant(
            authorizationGrantId,
            acr,
            amr,
            CancellationToken.None);
    }

    protected async Task Consent(string subjectIdentifier, string clientId, IReadOnlyCollection<string> scopes, IReadOnlyCollection<string> claims)
    {
        var consentRepository = ServiceProvider.GetRequiredService<IConsentRepository>();
        await consentRepository.CreateOrUpdateClientConsent(subjectIdentifier, clientId, scopes, claims, CancellationToken.None);
    }

    protected async Task<string> AddWeatherReadScope()
    {
        var dbContext = ServiceProvider.GetRequiredService<AuthorizationDbContext>();

        const string scopeName = "weather:read";
        var scope = new Scope(scopeName);

        await dbContext.AddAsync(scope);
        await dbContext.SaveChangesAsync();

        return scopeName;
    }

    protected async Task<Client> AddWeatherClient(string plainSecret)
    {
        var dbContext = ServiceProvider.GetRequiredService<AuthorizationDbContext>();

        var weatherScope = await dbContext.Set<Scope>().SingleAsync(x => x.Name == "weather:read");
        var client = new Client("weather-api", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic)
        {
            Scopes = [weatherScope],
            ClientUri = "https://weather.authserver.dk"
        };

        client.SetSecret(CryptographyHelper.HashPassword(plainSecret));

        await dbContext.AddAsync(client);
        await dbContext.SaveChangesAsync();

        return client;
    }

    protected async Task<Client> AddIdentityProviderClient()
    {
        var dbContext = ServiceProvider.GetRequiredService<AuthorizationDbContext>();

        var userinfoScope = await dbContext.Set<Scope>().SingleAsync(x => x.Name == ScopeConstants.UserInfo);
        var grantManagementRevokeScope = await dbContext.Set<Scope>().SingleAsync(x => x.Name == ScopeConstants.GrantManagementRevoke);
        var grantManagementQueryScope = await dbContext.Set<Scope>().SingleAsync(x => x.Name == ScopeConstants.GrantManagementQuery);

        var openId = await dbContext.Set<Scope>().SingleAsync(x => x.Name == ScopeConstants.OpenId);
        var email = await dbContext.Set<Scope>().SingleAsync(x => x.Name == ScopeConstants.Email);
        var address = await dbContext.Set<Scope>().SingleAsync(x => x.Name == ScopeConstants.Address);
        var phone = await dbContext.Set<Scope>().SingleAsync(x => x.Name == ScopeConstants.Phone);
        var profile = await dbContext.Set<Scope>().SingleAsync(x => x.Name == ScopeConstants.Profile);
        var offlineAccess = await dbContext.Set<Scope>().SingleAsync(x => x.Name == ScopeConstants.OfflineAccess);

        var client = new Client("identity-provider", ApplicationType.Web, TokenEndpointAuthMethod.ClientSecretBasic)
        {
            Scopes = [openId, email, address, phone, profile, offlineAccess, userinfoScope, grantManagementRevokeScope, grantManagementQueryScope],
            ClientUri = "https://localhost:7254"
        };

        await dbContext.AddAsync(client);
        await dbContext.SaveChangesAsync();

        return client;
    }

    protected async Task AddUser()
    {
        var dbContext = ServiceProvider.GetRequiredService<AuthorizationDbContext>();

        var subjectIdentifier = new SubjectIdentifier();
        typeof(SubjectIdentifier)
            .GetProperty(nameof(SubjectIdentifier.Id))!
            .SetValue(subjectIdentifier, UserConstants.SubjectIdentifier);

        await dbContext.AddAsync(subjectIdentifier);
        await dbContext.SaveChangesAsync();
    }

    protected async Task AddAuthenticationContextReferences()
    {
        var dbContext = ServiceProvider.GetRequiredService<AuthorizationDbContext>();

        var authenticationContextReferenceLow = new AuthenticationContextReference(LevelOfAssuranceLow);
        var authenticationContextReferenceSubstantial = new AuthenticationContextReference(LevelOfAssuranceSubstantial);
        var authenticationContextReferenceStrict = new AuthenticationContextReference(LevelOfAssuranceStrict);

        dbContext.AddRange(
            authenticationContextReferenceLow,
            authenticationContextReferenceSubstantial,
            authenticationContextReferenceStrict);

        await dbContext.SaveChangesAsync();
    }
}