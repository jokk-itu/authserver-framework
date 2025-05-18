using AuthServer.Authentication;
using AuthServer.Authentication.Abstractions;
using AuthServer.Authentication.OAuthToken;
using AuthServer.Authorization;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorize;
using AuthServer.Authorize.Abstractions;
using AuthServer.Authorize.UserInterface;
using AuthServer.Authorize.UserInterface.Abstractions;
using AuthServer.BackgroundServices;
using AuthServer.Cache;
using AuthServer.Cache.Abstractions;
using AuthServer.Codes;
using AuthServer.Codes.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.Discovery;
using AuthServer.Endpoints;
using AuthServer.Endpoints.Abstractions;
using AuthServer.EndSession;
using AuthServer.EndSession.UserInterface;
using AuthServer.EndSession.UserInterface.Abstractions;
using AuthServer.GrantManagement;
using AuthServer.GrantManagement.Query;
using AuthServer.GrantManagement.Revoke;
using AuthServer.Introspection;
using AuthServer.Jwks;
using AuthServer.Metrics;
using AuthServer.Metrics.Abstractions;
using AuthServer.Options;
using AuthServer.PushedAuthorization;
using AuthServer.Register;
using AuthServer.Repositories;
using AuthServer.Repositories.Abstractions;
using AuthServer.Revocation;
using AuthServer.TokenBuilders;
using AuthServer.TokenBuilders.Abstractions;
using AuthServer.TokenByGrant;
using AuthServer.TokenByGrant.AuthorizationCodeGrant;
using AuthServer.TokenByGrant.ClientCredentialsGrant;
using AuthServer.TokenByGrant.RefreshTokenGrant;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;
using AuthServer.Userinfo;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.FeatureManagement;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddAuthServer(this IServiceCollection services,
        Action<IServiceProvider, DbContextOptionsBuilder> databaseConfigurator)
    {
        services.AddScopedFeatureManagement();
        services.AddDataProtection();
        services.AddSingleton<IMetricService, MetricService>();
        services.AddScoped<IEndpointResolver, EndpointResolver>();
        services.AddHttpContextAccessor();
        services.AddHttpClient(
            HttpClientNameConstants.Client, client =>
            {
                client.Timeout = TimeSpan.FromSeconds(2);
                client.MaxResponseContentBufferSize = 1024 * 32;
            });

        services
            .AddDbContext<AuthorizationDbContext>(databaseConfigurator)
            .AddScoped<IUnitOfWork, UnitOfWork>()
            .AddScoped<ICachedClientStore, CachedClientStore>()
            .AddScoped<ITokenReplayCache, TokenReplayCache>();

        services
            .AddScoped<ITokenDecoder<ServerIssuedTokenDecodeArguments>, ServerIssuedTokenDecoder>()
            .AddScoped<ITokenDecoder<ClientIssuedTokenDecodeArguments>, ClientIssuedTokenDecoder>()
            .AddScoped<IAuthorizationCodeEncoder, AuthorizationCodeEncoder>();

        AddBackgroundServices(services);
        AddClientServices(services);
        AddAuthServerAuthentication(services);
        AddAuthServerAuthorization(services);
        AddAuthServerOptions(services);
        AddTokenBuilders(services);
        AddRepositories(services);
        AddAuthorize(services);
        AddToken(services);
        AddUserinfo(services);
        AddEndSession(services);
        AddIntrospection(services);
        AddRevocation(services);
        AddPushedAuthorization(services);
        AddRegister(services);
        AddGrantManagement(services);
        AddDiscovery(services);
        AddJwks(services);

        return services;
    }

    private static void AddBackgroundServices(IServiceCollection services)
    {
        services
            .AddHostedService<SessionCleanupBackgroundService>()
            .AddHostedService<AuthorizationGrantCleanupBackgroundService>()
            .AddHostedService<TokenCleanupBackgroundService>();
    }

    private static void AddClientServices(IServiceCollection services)
    {
        services
            .AddScoped<IClientAuthenticationService, ClientAuthenticationService>()
            .AddScoped<IClientJwkService, ClientJwkService>()
            .AddScoped<IClientSectorService, ClientSectorService>()
            .AddScoped<IClientLogoutService, ClientLogoutService>()
            .AddScoped<ISecureRequestService, SecureRequestService>()
            .AddScoped<IDPoPService, DPoPService>();
    }

    private static void AddRepositories(IServiceCollection services)
    {
        services
            .AddScoped<IClientRepository, ClientRepository>()
            .AddScoped<IConsentRepository, ConsentRepository>()
            .AddScoped<IAuthorizationGrantRepository, AuthorizationGrantRepository>()
            .AddScoped<ITokenRepository, TokenRepository>()
            .AddScoped<INonceRepository, NonceRepository>()
            .AddScoped<ISessionRepository, SessionRepository>();
    }

    private static void AddAuthServerOptions(IServiceCollection services)
    {
        services
            .ConfigureOptions<PostConfigureDiscoveryDocumentOptions>()
            .ConfigureOptions<ValidateDiscoveryDocumentOptions>()
            .ConfigureOptions<ValidateJwksDocument>()
            .ConfigureOptions<ValidateUserInteractionOptions>();
    }
    
    private static void AddTokenBuilders(IServiceCollection services)
    {
        services
            .AddScoped<ITokenBuilder<LogoutTokenArguments>, LogoutTokenBuilder>()
            .AddScoped<ITokenBuilder<IdTokenArguments>, IdTokenBuilder>()
            .AddScoped<ITokenBuilder<ClientAccessTokenArguments>, ClientAccessTokenBuilder>()
            .AddScoped<ITokenBuilder<GrantAccessTokenArguments>, GrantAccessTokenBuilder>()
            .AddScoped<ITokenBuilder<RefreshTokenArguments>, RefreshTokenBuilder>()
            .AddScoped<ITokenBuilder<RegistrationTokenArguments>, RegistrationTokenBuilder>()
            .AddScoped<ITokenBuilder<UserinfoTokenArguments>, UserinfoTokenBuilder>()
            .AddScoped<ITokenSecurityService, TokenSecurityService>();
    }

    private static void AddAuthServerAuthentication(IServiceCollection services)
    {
        services
            .AddAuthentication()
            .AddScheme<OAuthTokenAuthenticationOptions, OAuthTokenAuthenticationHandler>(
                OAuthTokenAuthenticationDefaults.AuthenticationScheme, null);
    }

    private static void AddAuthServerAuthorization(IServiceCollection services)
    {
        services
            .AddAuthorizationBuilder()
            .AddPolicy(AuthorizationConstants.Userinfo, policy =>
            {
                policy.AddAuthenticationSchemes(OAuthTokenAuthenticationDefaults.AuthenticationScheme);
                policy.RequireAssertion(context =>
                {
                    var scope = context.User.Claims.SingleOrDefault(x => x.Type == ClaimNameConstants.Scope)?.Value;
                    return scope is not null && scope.Split(' ').Contains(ScopeConstants.UserInfo);
                });
            })
            .AddPolicy(AuthorizationConstants.Register, policy =>
            {
                policy.AddAuthenticationSchemes(OAuthTokenAuthenticationDefaults.AuthenticationScheme);
                policy.RequireClaim(ClaimNameConstants.Scope, ScopeConstants.Register);
            })
            .AddPolicy(AuthorizationConstants.GrantManagementQuery, policy =>
            {
                policy.AddAuthenticationSchemes(OAuthTokenAuthenticationDefaults.AuthenticationScheme);
                policy.RequireAssertion(context =>
                {
                    var scope = context.User.Claims.SingleOrDefault(x => x.Type == ClaimNameConstants.Scope)?.Value;
                    return scope is not null && scope.Split(' ').Contains(ScopeConstants.GrantManagementQuery);
                });
            })
            .AddPolicy(AuthorizationConstants.GrantManagementRevoke, policy =>
            {
                policy.AddAuthenticationSchemes(OAuthTokenAuthenticationDefaults.AuthenticationScheme);
                policy.RequireAssertion(context =>
                {
                    var scope = context.User.Claims.SingleOrDefault(x => x.Type == ClaimNameConstants.Scope)?.Value;
                    return scope is not null && scope.Split(' ').Contains(ScopeConstants.GrantManagementRevoke);
                });
            });
    }

    private static void AddPushedAuthorization(IServiceCollection services)
    {
        services
            .AddKeyedScoped<IEndpointHandler, PushedAuthorizationEndpointHandler>(EndpointNameConstants.PushedAuthorization)
            .AddSingleton<IEndpointModule, PushedAuthorizationEndpointModule>()
            .AddScoped<IRequestAccessor<PushedAuthorizationRequest>, PushedAuthorizationRequestAccessor>()
            .AddScoped<IRequestHandler<PushedAuthorizationRequest, PushedAuthorizationResponse>, PushedAuthorizationRequestHandler>()
            .AddScoped<IRequestProcessor<PushedAuthorizationValidatedRequest, PushedAuthorizationResponse>, PushedAuthorizationRequestProcessor>()
            .AddScoped<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>, PushedAuthorizationRequestValidator>();
    }

    private static void AddRegister(IServiceCollection services)
    {
        services
            .AddScoped<IRequestAccessor<RegisterRequest>, RegisterRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, RegisterEndpointHandler>(EndpointNameConstants.Register)
            .AddSingleton<IEndpointModule, RegisterEndpointModule>()
            .AddScoped<IRequestHandler<RegisterRequest, ProcessResult<RegisterResponse, Unit>>, RegisterRequestHandler>()
            .AddScoped<IRequestValidator<RegisterRequest, RegisterValidatedRequest>, RegisterRequestValidator>()
            .AddScoped<IRequestProcessor<RegisterValidatedRequest, ProcessResult<RegisterResponse, Unit>>, RegisterRequestProcessor>();
    }

    private static void AddEndSession(IServiceCollection services)
    {
        services
            .AddScoped<IRequestAccessor<EndSessionRequest>, EndSessionRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, EndSessionEndpointHandler>(EndpointNameConstants.EndSession)
            .AddSingleton<IEndpointModule, EndSessionEndpointModule>()
            .AddScoped<IUserAccessor<EndSessionUser>, EndSessionUserAccessor>()
            .AddScoped<IRequestHandler<EndSessionRequest, Unit>, EndSessionRequestHandler>()
            .AddScoped<IRequestValidator<EndSessionRequest, EndSessionValidatedRequest>, EndSessionRequestValidator>()
            .AddScoped<IRequestProcessor<EndSessionValidatedRequest, Unit>, EndSessionRequestProcessor>()
            .AddScoped<IEndSessionService, EndSessionService>();
    }

    private static void AddAuthorize(IServiceCollection services)
    {
        services
            .AddScoped<IRequestAccessor<AuthorizeRequest>, AuthorizeRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, AuthorizeEndpointHandler>(EndpointNameConstants.Authorize)
            .AddSingleton<IEndpointModule, AuthorizeEndpointModule>()
            .AddScoped<IAuthorizeService, AuthorizeService>()
            .AddScoped<IAuthorizeInteractionService, AuthorizeInteractionService>()
            .AddScoped<IAuthorizeResponseBuilder, AuthorizeResponseBuilder>()
            .AddScoped<IUserAccessor<AuthorizeUser>, AuthorizeUserAccessor>()
            .AddScoped<IRequestHandler<AuthorizeRequest, string>, AuthorizeRequestHandler>()
            .AddScoped<IRequestProcessor<AuthorizeValidatedRequest, string>, AuthorizeRequestProcessor>()
            .AddScoped<IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>, AuthorizeRequestValidator>();
    }

    private static void AddUserinfo(IServiceCollection services)
    {
        services
            .AddScoped<IRequestAccessor<UserinfoRequest>, UserinfoRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, UserinfoEndpointHandler>(EndpointNameConstants.Userinfo)
            .AddSingleton<IEndpointModule, UserinfoEndpointModule>()
            .AddScoped<IRequestHandler<UserinfoRequest, string>, UserinfoRequestHandler>()
            .AddScoped<IRequestValidator<UserinfoRequest, UserinfoValidatedRequest>, UserinfoRequestValidator>()
            .AddScoped<IRequestProcessor<UserinfoValidatedRequest, string>, UserinfoRequestProcessor>();
    }

    private static void AddIntrospection(IServiceCollection services)
    {
        services
            .AddScoped<IRequestAccessor<IntrospectionRequest>, IntrospectionRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, IntrospectionEndpointHandler>(EndpointNameConstants.Introspection)
            .AddSingleton<IEndpointModule, IntrospectionEndpointModule>()
            .AddScoped<IRequestHandler<IntrospectionRequest, IntrospectionResponse>, IntrospectionRequestHandler>()
            .AddScoped<IRequestValidator<IntrospectionRequest, IntrospectionValidatedRequest>, IntrospectionRequestValidator>()
            .AddScoped<IRequestProcessor<IntrospectionValidatedRequest, IntrospectionResponse>, IntrospectionRequestProcessor>();
    }

    private static void AddRevocation(IServiceCollection services)
    {
        services
            .AddScoped<IRequestAccessor<RevocationRequest>, RevocationRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, RevocationEndpointHandler>(EndpointNameConstants.Revocation)
            .AddSingleton<IEndpointModule, RevocationEndpointModule>()
            .AddScoped<IRequestHandler<RevocationRequest, Unit>, RevocationRequestHandler>()
            .AddScoped<IRequestValidator<RevocationRequest, RevocationValidatedRequest>, RevocationRequestValidator>()
            .AddScoped<IRequestProcessor<RevocationValidatedRequest, Unit>, RevocationRequestProcessor>();
    }

    private static void AddToken(IServiceCollection services)
    {
        services
            .AddScoped<IRequestAccessor<TokenRequest>, TokenRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, TokenEndpointHandler>(EndpointNameConstants.Token)
            .AddSingleton<IEndpointModule, TokenEndpointModule>();

        services
            .AddKeyedScoped<IRequestHandler<TokenRequest, TokenResponse>, RefreshTokenRequestHandler>(GrantTypeConstants.RefreshToken)
            .AddScoped<IRequestProcessor<RefreshTokenValidatedRequest, TokenResponse>, RefreshTokenRequestProcessor>()
            .AddScoped<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>, RefreshTokenRequestValidator>();

        services
            .AddKeyedScoped<IRequestHandler<TokenRequest, TokenResponse>, AuthorizationCodeRequestHandler>(GrantTypeConstants.AuthorizationCode)
            .AddScoped<IRequestProcessor<AuthorizationCodeValidatedRequest, TokenResponse>, AuthorizationCodeRequestProcessor>()
            .AddScoped<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>, AuthorizationCodeRequestValidator>();

        services
            .AddKeyedScoped<IRequestHandler<TokenRequest, TokenResponse>, ClientCredentialsRequestHandler>(GrantTypeConstants.ClientCredentials)
            .AddScoped<IRequestProcessor<ClientCredentialsValidatedRequest, TokenResponse>, ClientCredentialsRequestProcessor>()
            .AddScoped<IRequestValidator<TokenRequest, ClientCredentialsValidatedRequest>, ClientCredentialsRequestValidator>();
    }

    private static void AddGrantManagement(IServiceCollection services)
    {
        services
            .AddScoped<IRequestAccessor<GrantManagementRequest>, GrantManagementRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, GrantManagementRevokeEndpointHandler>(EndpointNameConstants.GrantManagementRevoke)
            .AddKeyedScoped<IEndpointHandler, GrantManagementQueryEndpointHandler>(EndpointNameConstants.GrantManagementQuery)
            .AddSingleton<IEndpointModule, GrantManagementEndpointModule>()
            .AddScoped<IRequestHandler<GrantManagementRequest, Unit>, GrantManagementRevokeRequestHandler>()
            .AddScoped<IRequestHandler<GrantManagementRequest, GrantResponse>, GrantManagementQueryRequestHandler>()
            .AddScoped<IRequestValidator<GrantManagementRequest, GrantManagementValidatedRequest>, GrantManagementRequestValidator>()
            .AddScoped<IRequestProcessor<GrantManagementValidatedRequest, Unit>, GrantManagementRevokeRequestProcessor>()
            .AddScoped<IRequestProcessor<GrantManagementValidatedRequest, GrantResponse>, GrantManagementQueryRequestProcessor>();
    }

    private static void AddDiscovery(IServiceCollection services)
    {
        services
            .AddKeyedScoped<IEndpointHandler, DiscoveryEndpointHandler>(EndpointNameConstants.Discovery)
            .AddSingleton<IEndpointModule, DiscoveryEndpointModule>();
    }

    private static void AddJwks(IServiceCollection services)
    {
        services
            .AddKeyedScoped<IEndpointHandler, JwksEndpointHandler>(EndpointNameConstants.Jwks)
            .AddSingleton<IEndpointModule, JwksEndpointModule>();
    }
}