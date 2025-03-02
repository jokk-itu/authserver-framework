﻿using AuthServer.Authentication.Abstractions;
using AuthServer.Authorize.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Endpoints.Abstractions;
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
    private readonly IDataProtectionProvider _dataProtectionProvider;

    protected readonly ITestOutputHelper TestOutputHelper;
    protected readonly IServiceProvider ServiceProvider;

    protected AuthorizeEndpointBuilder AuthorizeEndpointBuilder => new AuthorizeEndpointBuilder(
        GetHttpClient(),
        _dataProtectionProvider,
        DiscoveryDocument,
        JwksDocument,
        EndpointResolver,
        TestOutputHelper);

    protected RegisterEndpointBuilder RegisterEndpointBuilder => new RegisterEndpointBuilder(
        GetHttpClient(),
        DiscoveryDocument,
        JwksDocument,
        EndpointResolver,
        TestOutputHelper);

    protected IntrospectionEndpointBuilder IntrospectionEndpointBuilder => new IntrospectionEndpointBuilder(
        GetHttpClient(),
        DiscoveryDocument,
        JwksDocument,
        EndpointResolver,
        TestOutputHelper);

    protected RevocationEndpointBuilder RevocationEndpointBuilder => new RevocationEndpointBuilder(
        GetHttpClient(),
        DiscoveryDocument,
        JwksDocument,
        EndpointResolver,
        TestOutputHelper);

    protected UserinfoEndpointBuilder UserinfoEndpointBuilder => new UserinfoEndpointBuilder(
        GetHttpClient(),
        DiscoveryDocument,
        JwksDocument,
        EndpointResolver,
        TestOutputHelper);

    protected PushedAuthorizationEndpointBuilder PushedAuthorizationEndpointBuilder => new PushedAuthorizationEndpointBuilder(
        GetHttpClient(),
        DiscoveryDocument,
        JwksDocument,
        EndpointResolver,
        TestOutputHelper);

    protected GrantManagementEndpointBuilder GrantManagementEndpointBuilder => new GrantManagementEndpointBuilder(
        GetHttpClient(),
        DiscoveryDocument,
        JwksDocument,
        EndpointResolver,
        TestOutputHelper);

    protected TokenEndpointBuilder TokenEndpointBuilder => new(GetHttpClient(), DiscoveryDocument, JwksDocument, EndpointResolver, TestOutputHelper);

    private readonly IOptionsMonitor<DiscoveryDocument> _discoveryDocumentOptions;
    protected DiscoveryDocument DiscoveryDocument => _discoveryDocumentOptions.CurrentValue;

    private readonly IOptionsMonitor<UserInteraction> _userInteractionOptions;
    protected UserInteraction UserInteraction => _userInteractionOptions.CurrentValue;

    private readonly IOptionsMonitor<JwksDocument> _jwksDocumentOptions;
    protected JwksDocument JwksDocument => _jwksDocumentOptions.CurrentValue;

    protected IEndpointResolver EndpointResolver { get; }

    protected JwtBuilder JwtBuilder => new (DiscoveryDocument, JwksDocument, EndpointResolver);

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

        _dataProtectionProvider = ServiceProvider.GetRequiredService<IDataProtectionProvider>();
        _discoveryDocumentOptions = _factory.Services.GetRequiredService<IOptionsMonitor<DiscoveryDocument>>();
        _userInteractionOptions = _factory.Services.GetRequiredService<IOptionsMonitor<UserInteraction>>();
        _jwksDocumentOptions = _factory.Services.GetRequiredService<IOptionsMonitor<JwksDocument>>();
        EndpointResolver = _factory.Services.GetRequiredService<IEndpointResolver>();

        ServiceProvider.GetRequiredService<AuthorizationDbContext>().Database.EnsureDeleted();
        ServiceProvider.GetRequiredService<AuthorizationDbContext>().Database.Migrate();
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