using System.Security.Cryptography;
using AuthServer.Authentication.Abstractions;
using AuthServer.Authorize.Abstractions;
using AuthServer.Cache.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Endpoints.Abstractions;
using AuthServer.Entities;
using AuthServer.Enums;
using AuthServer.Extensions;
using AuthServer.Options;
using AuthServer.Tests.Core;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Xunit.Abstractions;

namespace AuthServer.Tests.UnitTest;

public abstract class BaseUnitTest
{
    private readonly SqliteConnection _connection;
    internal AuthorizationDbContext IdentityContext = null!;

    private readonly RsaSecurityKey RsaSecurityKey = new RsaSecurityKey(RSA.Create(3072))
    {
        KeyId = Guid.NewGuid().ToString()
    };

    private readonly ECDsaSecurityKey ECDsaSecurityKey = new ECDsaSecurityKey(ECDsa.Create())
    {
        KeyId = Guid.NewGuid().ToString()
    };

    protected ITestOutputHelper OutputHelper;
    protected JwtBuilder JwtBuilder = null!;
    protected DiscoveryDocument DiscoveryDocument = null!;
    protected JwksDocument JwksDocument = null!;
    protected IEndpointResolver EndpointResolver = null!;
    protected UserInteraction UserInteraction = null!;
    protected SigningAlg TokenSigningAlg = SigningAlg.RsaSha256;

    protected const string LevelOfAssuranceLow = AuthenticationContextReferenceConstants.LevelOfAssuranceLow;
    protected const string LevelOfAssuranceSubstantial = AuthenticationContextReferenceConstants.LevelOfAssuranceSubstantial;
    protected const string LevelOfAssuranceStrict = AuthenticationContextReferenceConstants.LevelOfAssuranceStrict;

    protected BaseUnitTest(ITestOutputHelper outputHelper)
    {
        IdentityModelEventSource.ShowPII = true;
        _connection = new SqliteConnection("Data Source=:memory:");
        _connection.Open();
        OutputHelper = outputHelper;
    }

    protected Task SaveChangesAsync() => IdentityContext.SaveChangesAsync();
    protected Task<Scope> GetScope(string name) => IdentityContext.Set<Scope>().SingleAsync(x => x.Name == name);
    protected Task<GrantType> GetGrantType(string name) => IdentityContext.Set<GrantType>().SingleAsync(x => x.Name == name);
    protected Task<ResponseType> GetResponseType(string name) => IdentityContext.Set<ResponseType>().SingleAsync(x => x.Name == name);
    protected Task<AuthenticationMethodReference> GetAuthenticationMethodReference(string name) => IdentityContext.Set<AuthenticationMethodReference>().SingleAsync(x => x.Name == name);
    protected Task<AuthenticationContextReference> GetAuthenticationContextReference(string name) => IdentityContext.Set<AuthenticationContextReference>().SingleAsync(x => x.Name == name);
    protected Task<Claim> GetClaim(string name) => IdentityContext.Set<Claim>().SingleAsync(x => x.Name == name);
    
    protected async Task AddEntity<T>(T entity) where T : class
    {
        await IdentityContext.Set<T>().AddAsync(entity);
        await IdentityContext.SaveChangesAsync();
    }

    protected IServiceCollection ConfigureServices(IServiceCollection services)
    {
        services.AddOptions<DiscoveryDocument>().Configure(discoveryDocument =>
        {
            discoveryDocument.Issuer = "https://localhost:5000";
            discoveryDocument.ClaimsSupported = ClaimNameConstants.SupportedEndUserClaims;
            discoveryDocument.AcrValuesSupported =
                [LevelOfAssuranceLow, LevelOfAssuranceSubstantial, LevelOfAssuranceStrict];

            var supportedSigningAlgorithms = new[] { JwsAlgConstants.RsaSha256, JwsAlgConstants.EcdsaSha256 };
            var supportedEncryptionAlgorithms = new[] { JweAlgConstants.RsaPKCS1, JweAlgConstants.EcdhEsA128KW };
            var supportedEncryptionEncoding = new[] { JweEncConstants.Aes128CbcHmacSha256 };

            discoveryDocument.IntrospectionEndpointAuthSigningAlgValuesSupported = supportedSigningAlgorithms;
            discoveryDocument.RevocationEndpointAuthSigningAlgValuesSupported = supportedSigningAlgorithms;
            discoveryDocument.DPoPSigningAlgValuesSupported = supportedSigningAlgorithms;
            
            discoveryDocument.TokenEndpointAuthSigningAlgValuesSupported = supportedSigningAlgorithms;
            discoveryDocument.TokenEndpointAuthEncryptionAlgValuesSupported = supportedEncryptionAlgorithms;
            discoveryDocument.TokenEndpointAuthEncryptionEncValuesSupported = supportedEncryptionEncoding;

            discoveryDocument.RequestObjectSigningAlgValuesSupported = supportedSigningAlgorithms;
            discoveryDocument.RequestObjectEncryptionAlgValuesSupported = supportedEncryptionAlgorithms;
            discoveryDocument.RequestObjectEncryptionEncValuesSupported = supportedEncryptionEncoding;

            discoveryDocument.UserinfoSigningAlgValuesSupported = supportedSigningAlgorithms;
            discoveryDocument.UserinfoEncryptionAlgValuesSupported = supportedEncryptionAlgorithms;
            discoveryDocument.UserinfoEncryptionEncValuesSupported = supportedEncryptionEncoding;

            discoveryDocument.IdTokenSigningAlgValuesSupported = supportedSigningAlgorithms;
            discoveryDocument.IdTokenEncryptionAlgValuesSupported = supportedEncryptionAlgorithms;
            discoveryDocument.IdTokenEncryptionEncValuesSupported = supportedEncryptionEncoding;
        });
        services.AddOptions<JwksDocument>().Configure(jwksDocument =>
        {
            jwksDocument.SigningKeys =
            [
                new(RsaSecurityKey, SigningAlg.RsaSha256),
                new(RsaSecurityKey, SigningAlg.RsaSha384),
                new(RsaSecurityKey, SigningAlg.RsaSha512),
                new(RsaSecurityKey, SigningAlg.RsaSsaPssSha256),
                new(RsaSecurityKey, SigningAlg.RsaSsaPssSha384),
                new(RsaSecurityKey, SigningAlg.RsaSsaPssSha512),
                new(ECDsaSecurityKey, SigningAlg.EcdsaSha256),
                new(ECDsaSecurityKey, SigningAlg.EcdsaSha384),
                new(ECDsaSecurityKey, SigningAlg.EcdsaSha512),
            ];

            jwksDocument.EncryptionKeys =
            [
                new(RsaSecurityKey, EncryptionAlg.RsaOAEP),
                new(RsaSecurityKey, EncryptionAlg.RsaPKCS1),
                new(ECDsaSecurityKey, EncryptionAlg.EcdhEsA128KW),
                new(ECDsaSecurityKey, EncryptionAlg.EcdhEsA192KW),
                new(ECDsaSecurityKey, EncryptionAlg.EcdhEsA256KW)
            ];

            jwksDocument.GetTokenSigningKey =
                () => jwksDocument.SigningKeys.Single(x => x.Alg == TokenSigningAlg);
        });
        services.AddOptions<UserInteraction>().Configure(userInteraction =>
        {
            userInteraction.LoginUri = "https://localhost:5000/login";
            userInteraction.ConsentUri = "https://localhost:5000/consent";
            userInteraction.AccountSelectionUri = "https://localhost:5000/select-account";
            userInteraction.EndSessionUri = "https://localhost:5000/logout";
            userInteraction.VerificationUri = "https://localhost:5000/device";
        });

        services
            .AddAuthServer()
            .AddCleanupBackgroundServices()
            .AddJwksHttpClient()
            .AddLogoutHttpClient()
            .AddRequestHttpClient()
            .AddSectorHttpClient()
            .AddAuthorizationCode()
            .AddClientCredentials()
            .AddRefreshToken()
            .AddDeviceCode()
            .AddTokenExchange()
            .AddRevocation()
            .AddIntrospection()
            .AddDiscovery()
            .AddJwks()
            .AddGrantManagementQuery()
            .AddGrantManagementRevoke()
            .AddEndSession()
            .AddUserinfo()
            .AddRegister()
            .AddPushedAuthorization()
            .AddAuthorizationDbContext((_, contextOptions) =>
            {
                contextOptions.UseSqlite(_connection,
                    optionsBuilder =>
                    {
                        optionsBuilder.UseQuerySplittingBehavior(QuerySplittingBehavior.SplitQuery);
                    });
            });

        services.AddScoped<IDistributedCache, InMemoryCache>();
        services.AddScoped<IUserClaimService, UserClaimService>();
        services.AddScoped<IAuthenticatedUserAccessor, AuthenticatedUserAccessor>();
        services.AddScoped<IAuthenticationContextReferenceResolver, AuthenticationContextReferenceResolver>();

        return services;
    }

    protected IServiceProvider BuildServiceProvider(Action<IServiceCollection>? configure = null)
    {
        var services = new ServiceCollection();
        ConfigureServices(services);
        configure?.Invoke(services);
        var serviceProvider = services.BuildServiceProvider();
        var identityContext = serviceProvider.GetRequiredService<AuthorizationDbContext>();
        IdentityContext = identityContext;
        IdentityContext.Database.EnsureCreated();

        CreateAuthenticationContextReferences().GetAwaiter().GetResult();

        var discoveryDocument = serviceProvider.GetRequiredService<IOptionsSnapshot<DiscoveryDocument>>();
        DiscoveryDocument = discoveryDocument.Value;

        var jwksDocument = serviceProvider.GetRequiredService<IOptionsSnapshot<JwksDocument>>();
        JwksDocument = jwksDocument.Value;

        var endpointResolver = serviceProvider.GetRequiredService<IEndpointResolver>();
        EndpointResolver = endpointResolver;

        JwtBuilder = new JwtBuilder(DiscoveryDocument, JwksDocument, EndpointResolver);

        var userInteraction = serviceProvider.GetRequiredService<IOptionsSnapshot<UserInteraction>>();
        UserInteraction = userInteraction.Value;

        return serviceProvider;
    }

    private async Task CreateAuthenticationContextReferences()
    {
        var authenticationContextReferenceLow = new AuthenticationContextReference(LevelOfAssuranceLow);
        var authenticationContextReferenceSubstantial = new AuthenticationContextReference(LevelOfAssuranceSubstantial);
        var authenticationContextReferenceStrict = new AuthenticationContextReference(LevelOfAssuranceStrict);
        await AddEntity(authenticationContextReferenceLow);
        await AddEntity(authenticationContextReferenceSubstantial);
        await AddEntity(authenticationContextReferenceStrict);
    }
}