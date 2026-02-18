using AuthServer.Cache.Abstractions;
using AuthServer.Constants;
using AuthServer.Enums;
using AuthServer.Extensions;
using Microsoft.EntityFrameworkCore;
using AuthServer.Tests.Core;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Logging;
using AuthServer.Options;
using AuthServer.Authorize.Abstractions;
using AuthServer.Authentication.Abstractions;
using AuthServer.TestIdentityProvider;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme,
        options => { options.Cookie.Name = "AuthServer.Identity"; });

builder.Services
    .AddOptions<DiscoveryDocument>()
    .Configure(options =>
    {
        var identitySection = builder.Configuration.GetSection("Identity");
        options.Issuer = identitySection.GetValue<string>("Issuer")!;
        options.OpPolicyUri = identitySection.GetValue<string>("PolicyUri");
        options.OpTosUri = identitySection.GetValue<string>("TosUri");
        options.ClaimsSupported = ClaimNameConstants.SupportedEndUserClaims;
        options.AcrValuesSupported =
        [
            AuthenticationContextReferenceConstants.LevelOfAssuranceLow,
            AuthenticationContextReferenceConstants.LevelOfAssuranceSubstantial,
            AuthenticationContextReferenceConstants.LevelOfAssuranceStrict
        ];
        options.ScopesSupported = identitySection.GetSection("ScopesSupported").Get<ICollection<string>>() ?? [];
        options.ProtectedResources = identitySection.GetSection("ProtectedResources").Get<ICollection<string>>() ?? [];

        ICollection<string> signingAlgorithms =
            [JwsAlgConstants.RsaSha256, JwsAlgConstants.RsaSha384, JwsAlgConstants.RsaSha512,
                JwsAlgConstants.EcdsaSha256, JwsAlgConstants.EcdsaSha384, JwsAlgConstants.EcdsaSha512,
                JwsAlgConstants.RsaSsaPssSha256, JwsAlgConstants.RsaSsaPssSha384, JwsAlgConstants.RsaSsaPssSha512];

        ICollection<string> encryptionAlgorithms =
            [JweAlgConstants.EcdhEsA128KW, JweAlgConstants.EcdhEsA192KW, JweAlgConstants.EcdhEsA256KW,
                JweAlgConstants.RsaOAEP, JweAlgConstants.RsaPKCS1];

        ICollection<string> encoderAlgorithms =
            [JweEncConstants.Aes128CbcHmacSha256, JweEncConstants.Aes192CbcHmacSha384, JweEncConstants.Aes256CbcHmacSha512];

        options.TokenEndpointAuthSigningAlgValuesSupported = signingAlgorithms;
        options.IdTokenSigningAlgValuesSupported = signingAlgorithms;
        options.IntrospectionEndpointAuthSigningAlgValuesSupported = signingAlgorithms;
        options.DPoPSigningAlgValuesSupported = signingAlgorithms;
        options.RequestObjectSigningAlgValuesSupported = signingAlgorithms;
        options.RevocationEndpointAuthSigningAlgValuesSupported = signingAlgorithms;
        options.UserinfoSigningAlgValuesSupported = signingAlgorithms;

        options.IdTokenEncryptionAlgValuesSupported = encryptionAlgorithms;
        options.RequestObjectEncryptionAlgValuesSupported = encryptionAlgorithms;
        options.UserinfoEncryptionAlgValuesSupported = encryptionAlgorithms;
        options.TokenEndpointAuthEncryptionAlgValuesSupported = encryptionAlgorithms;

        options.IdTokenEncryptionEncValuesSupported = encoderAlgorithms;
        options.RequestObjectEncryptionEncValuesSupported = encoderAlgorithms;
        options.UserinfoEncryptionEncValuesSupported = encoderAlgorithms;
        options.TokenEndpointAuthEncryptionEncValuesSupported = encoderAlgorithms;
    });

builder.Services
    .AddOptions<JwksDocument>()
    .Configure(options =>
    {
        options.EncryptionKeys =
        [
            new EncryptionKey(SecurityKeyHelper.EcdhEs128, EncryptionAlg.EcdhEsA128KW),
            new EncryptionKey(SecurityKeyHelper.EcdhEs192, EncryptionAlg.EcdhEsA192KW),
            new EncryptionKey(SecurityKeyHelper.EcdhEs256, EncryptionAlg.EcdhEsA256KW),
            new EncryptionKey(SecurityKeyHelper.RsaOAep, EncryptionAlg.RsaOAEP),
            new EncryptionKey(SecurityKeyHelper.RsaPkcs1, EncryptionAlg.RsaPKCS1),
        ];
        options.SigningKeys =
        [
            new SigningKey(SecurityKeyHelper.Ecdsa256, SigningAlg.EcdsaSha256),
            new SigningKey(SecurityKeyHelper.Ecdsa384, SigningAlg.EcdsaSha384),
            new SigningKey(SecurityKeyHelper.Ecdsa512, SigningAlg.EcdsaSha512),
            new SigningKey(SecurityKeyHelper.CertificateRsa256, SigningAlg.RsaSha256),
            new SigningKey(SecurityKeyHelper.CertificateRsa384, SigningAlg.RsaSha384),
            new SigningKey(SecurityKeyHelper.CertificateRsa512, SigningAlg.RsaSha512),
            new SigningKey(SecurityKeyHelper.RsaSsaPss256, SigningAlg.RsaSsaPssSha256),
            new SigningKey(SecurityKeyHelper.RsaSsaPss384, SigningAlg.RsaSsaPssSha384),
            new SigningKey(SecurityKeyHelper.RsaSsaPss512, SigningAlg.RsaSsaPssSha512)
        ];

        options.GetTokenSigningKey =
            () => options.SigningKeys.Single(x => x.Alg == SigningAlg.RsaSha256);
    });

builder.Services
    .AddOptions<CleanupOptions>()
    .Configure(options =>
    {
        options.RunSessionCleanup = true;
        options.SessionCleanupIntervalInSeconds = 5;
        options.SessionCleanupBatchSize = 100;

        options.RunAuthorizationGrantCleanup = true;
        options.AuthorizationGrantCleanupIntervalInSeconds = 5;
        options.AuthorizationGrantCleanupBatchSize = 100;

        options.RunTokenCleanup = true;
        options.RunTokenCleanupIntervalInSeconds = 5;
        options.RunTokenCleanupBatchSize = 100;
    });

builder.Services
    .AddOptions<UserInteraction>()
    .Configure(options =>
    {
        var identity = builder.Configuration.GetSection("Identity");
        options.AccountSelectionUri = identity.GetValue<string>("AccountSelectionUri")!;
        options.ConsentUri = identity.GetValue<string>("ConsentUri")!;
        options.LoginUri = identity.GetValue<string>("LoginUri")!;
        options.EndSessionUri = identity.GetValue<string>("EndSessionUri")!;
        options.VerificationUri = identity.GetValue<string>("VerificationUri");
    });

builder.Services
    .AddOptions<TokenValidationOptions>()
    .Configure(options =>
    {
        options.ClockSkew = TimeSpan.FromSeconds(10);
    });

builder.Services.AddSingleton<IDistributedCache, InMemoryCache>();
builder.Services.AddScoped<IUserClaimService, UserClaimService>();
builder.Services.AddScoped<IAuthenticatedUserAccessor, AuthenticatedUserAccessor>();
builder.Services.AddScoped<IAuthenticationContextReferenceResolver, AuthenticationContextReferenceResolver>();

builder.Services
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
    .AddAuthorizationDbContext((_, dbContextConfigurator) =>
    {
        dbContextConfigurator.UseSqlServer(
            builder.Configuration.GetConnectionString("Default"),
            optionsBuilder =>
            {
                optionsBuilder.MigrationsAssembly("AuthServer.TestIdentityProvider");
                optionsBuilder.UseQuerySplittingBehavior(QuerySplittingBehavior.SplitQuery);
            });
    });

builder.Services.AddRazorPages();


var app = builder.Build();

IdentityModelEventSource.ShowPII = true;

app.UseHsts();
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseAuthServer();
app.MapRazorPages();

app.Run();

// Used ONLY for Tests.Integration
public partial class Program
{
}