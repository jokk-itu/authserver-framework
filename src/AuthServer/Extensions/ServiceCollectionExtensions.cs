using AuthServer.Authentication;
using AuthServer.Authentication.Abstractions;
using AuthServer.Authentication.OAuthToken;
using AuthServer.Authorization;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorize;
using AuthServer.Authorize.Abstractions;
using AuthServer.Authorize.UserInterface;
using AuthServer.Authorize.UserInterface.Abstractions;
using AuthServer.Cache;
using AuthServer.Cache.Abstractions;
using AuthServer.Codes;
using AuthServer.Codes.Abstractions;
using AuthServer.Constants;
using AuthServer.Core;
using AuthServer.Core.Abstractions;
using AuthServer.Core.Request;
using AuthServer.EndSession;
using AuthServer.EndSession.Abstractions;
using AuthServer.GrantManagement;
using AuthServer.GrantManagement.Revoke;
using AuthServer.Introspection;
using AuthServer.Metrics;
using AuthServer.Metrics.Abstractions;
using AuthServer.Options;
using AuthServer.PushedAuthorization;
using AuthServer.Register;
using AuthServer.Repositories;
using AuthServer.Repositories.Abstractions;
using AuthServer.RequestAccessors.Authorize;
using AuthServer.RequestAccessors.EndSession;
using AuthServer.RequestAccessors.GrantManagement;
using AuthServer.RequestAccessors.Introspection;
using AuthServer.RequestAccessors.PushedAuthorization;
using AuthServer.RequestAccessors.Register;
using AuthServer.RequestAccessors.Revocation;
using AuthServer.RequestAccessors.Token;
using AuthServer.RequestAccessors.Userinfo;
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
        services.AddHttpContextAccessor();
        services.AddHttpClient(HttpClientNameConstants.Client);

        services
            .AddDbContext<AuthorizationDbContext>(databaseConfigurator)
            .AddScoped<IUnitOfWork, UnitOfWork>()
            .AddScoped<ICachedClientStore, CachedClientStore>()
            .AddScoped<ITokenReplayCache, TokenReplayCache>();

        services
            .AddScoped<ITokenDecoder<ServerIssuedTokenDecodeArguments>, ServerIssuedTokenDecoder>()
            .AddScoped<ITokenDecoder<ClientIssuedTokenDecodeArguments>, ClientIssuedTokenDecoder>()
            .AddScoped<IAuthorizationCodeEncoder, AuthorizationCodeEncoder>();

        services
            .AddScoped<IClientAuthenticationService, ClientAuthenticationService>()
            .AddScoped<IClientJwkService, ClientJwkService>()
            .AddScoped<IClientSectorService, ClientSectorService>()
            .AddScoped<IClientLogoutService, ClientLogoutService>();

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

        return services;
    }

    private static IServiceCollection AddRepositories(IServiceCollection services)
    {
        return services
            .AddScoped<IClientRepository, ClientRepository>()
            .AddScoped<IConsentRepository, ConsentRepository>()
            .AddScoped<IAuthorizationGrantRepository, AuthorizationGrantRepository>()
            .AddScoped<ITokenRepository, TokenRepository>()
            .AddScoped<INonceRepository, NonceRepository>()
            .AddScoped<ISessionRepository, SessionRepository>();
    }

    private static IServiceCollection AddAuthServerOptions(IServiceCollection services)
    {
        return services
            .ConfigureOptions<PostConfigureDiscoveryDocumentOptions>()
            .ConfigureOptions<ValidateDiscoveryDocumentOptions>()
            .ConfigureOptions<ValidateJwksDocument>()
            .ConfigureOptions<ValidateUserInteractionOptions>();
    }
    
    private static IServiceCollection AddTokenBuilders(IServiceCollection services)
    {
        return services
            .AddScoped<ITokenBuilder<LogoutTokenArguments>, LogoutTokenBuilder>()
            .AddScoped<ITokenBuilder<IdTokenArguments>, IdTokenBuilder>()
            .AddScoped<ITokenBuilder<ClientAccessTokenArguments>, ClientAccessTokenBuilder>()
            .AddScoped<ITokenBuilder<GrantAccessTokenArguments>, GrantAccessTokenBuilder>()
            .AddScoped<ITokenBuilder<RefreshTokenArguments>, RefreshTokenBuilder>()
            .AddScoped<ITokenBuilder<RegistrationTokenArguments>, RegistrationTokenBuilder>()
            .AddScoped<ITokenBuilder<UserinfoTokenArguments>, UserinfoTokenBuilder>()
            .AddScoped<ITokenSecurityService, TokenSecurityService>();
    }

    private static IServiceCollection AddAuthServerAuthentication(IServiceCollection services)
    {
        services
            .AddAuthentication()
            .AddScheme<OAuthTokenAuthenticationOptions, OAuthTokenAuthenticationHandler>(
                OAuthTokenAuthenticationDefaults.AuthenticationScheme, null);
        
        return services;
    }

    private static IServiceCollection AddAuthServerAuthorization(IServiceCollection services)
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
        
        return services;
    }

    private static IServiceCollection AddPushedAuthorization(IServiceCollection services)
    {
        return services
            .AddKeyedScoped<IEndpointHandler, PushedAuthorizationEndpointHandler>("PushedAuthorization")
            .AddSingleton<IEndpointModule, PushedAuthorizationEndpointModule>()
            .AddScoped<IRequestAccessor<PushedAuthorizationRequest>, PushedAuthorizationRequestAccessor>()
            .AddScoped<IRequestHandler<PushedAuthorizationRequest, PushedAuthorizationResponse>, PushedAuthorizationRequestHandler>()
            .AddScoped<IRequestProcessor<PushedAuthorizationValidatedRequest, PushedAuthorizationResponse>, PushedAuthorizationRequestProcessor>()
            .AddScoped<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>, PushedAuthorizationRequestValidator>();
    }

    private static IServiceCollection AddRegister(IServiceCollection services)
    {
        return services
            .AddScoped<IRequestAccessor<RegisterRequest>, RegisterRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, RegisterEndpointHandler>("Register")
            .AddSingleton<IEndpointModule, RegisterEndpointModule>()
            .AddScoped<IRequestHandler<RegisterRequest, ProcessResult<RegisterResponse, Unit>>, RegisterRequestHandler>()
            .AddScoped<IRequestValidator<RegisterRequest, RegisterValidatedRequest>, RegisterRequestValidator>()
            .AddScoped<IRequestProcessor<RegisterValidatedRequest, ProcessResult<RegisterResponse, Unit>>, RegisterRequestProcessor>();
    }

    private static IServiceCollection AddEndSession(IServiceCollection services)
    {
        return services
            .AddScoped<IRequestAccessor<EndSessionRequest>, EndSessionRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, EndSessionEndpointHandler>("EndSession")
            .AddSingleton<IEndpointModule, EndSessionEndpointModule>()
            .AddScoped<IEndSessionUserAccessor, EndSessionUserAccessor>()
            .AddScoped<IRequestHandler<EndSessionRequest, Unit>, EndSessionRequestHandler>()
            .AddScoped<IRequestValidator<EndSessionRequest, EndSessionValidatedRequest>, EndSessionRequestValidator>()
            .AddScoped<IRequestProcessor<EndSessionValidatedRequest, Unit>, EndSessionRequestProcessor>();
    }

    private static IServiceCollection AddAuthorize(IServiceCollection services)
    {
        return services
            .AddScoped<IRequestAccessor<AuthorizeRequest>, AuthorizeRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, AuthorizeEndpointHandler>("Authorize")
            .AddSingleton<IEndpointModule, AuthorizeEndpointModule>()
            .AddScoped<IAuthorizeService, AuthorizeService>()
            .AddScoped<IAuthorizeInteractionService, AuthorizeInteractionService>()
            .AddScoped<IAuthorizeResponseBuilder, AuthorizeResponseBuilder>()
            .AddScoped<IAuthorizeUserAccessor, AuthorizeUserAccessor>()
            .AddScoped<ISecureRequestService, SecureRequestService>()
            .AddScoped<IRequestHandler<AuthorizeRequest, string>, AuthorizeRequestHandler>()
            .AddScoped<IRequestProcessor<AuthorizeValidatedRequest, string>, AuthorizeRequestProcessor>()
            .AddScoped<IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>, AuthorizeRequestValidator>();
    }

    private static IServiceCollection AddUserinfo(IServiceCollection services)
    {
        return services
            .AddScoped<IRequestAccessor<UserinfoRequest>, UserinfoRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, UserinfoEndpointHandler>("Userinfo")
            .AddSingleton<IEndpointModule, UserinfoEndpointModule>()
            .AddScoped<IRequestHandler<UserinfoRequest, string>, UserinfoRequestHandler>()
            .AddScoped<IRequestValidator<UserinfoRequest, UserinfoValidatedRequest>, UserinfoRequestValidator>()
            .AddScoped<IRequestProcessor<UserinfoValidatedRequest, string>, UserinfoRequestProcessor>();
    }

    private static IServiceCollection AddIntrospection(IServiceCollection services)
    {
        return services
            .AddScoped<IRequestAccessor<IntrospectionRequest>, IntrospectionRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, IntrospectionEndpointHandler>("Introspection")
            .AddSingleton<IEndpointModule, IntrospectionEndpointModule>()
            .AddScoped<IRequestHandler<IntrospectionRequest, IntrospectionResponse>, IntrospectionRequestHandler>()
            .AddScoped<IRequestValidator<IntrospectionRequest, IntrospectionValidatedRequest>, IntrospectionRequestValidator>()
            .AddScoped<IRequestProcessor<IntrospectionValidatedRequest, IntrospectionResponse>, IntrospectionRequestProcessor>();
    }

    private static IServiceCollection AddRevocation(IServiceCollection services)
    {
        return services
            .AddScoped<IRequestAccessor<RevocationRequest>, RevocationRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, RevocationEndpointHandler>("Revocation")
            .AddSingleton<IEndpointModule, RevocationEndpointModule>()
            .AddScoped<IRequestHandler<RevocationRequest, Unit>, RevocationRequestHandler>()
            .AddScoped<IRequestValidator<RevocationRequest, RevocationValidatedRequest>, RevocationRequestValidator>()
            .AddScoped<IRequestProcessor<RevocationValidatedRequest, Unit>, RevocationRequestProcessor>();
    }

    private static IServiceCollection AddToken(IServiceCollection services)
    {
        services
            .AddScoped<IRequestAccessor<TokenRequest>, TokenRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, TokenEndpointHandler>("Token")
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

        return services;
    }

    private static IServiceCollection AddGrantManagement(IServiceCollection services)
    {
        return services
            .AddScoped<IRequestAccessor<GrantManagementRequest>, GrantManagementRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, GrantManagementRevokeEndpointHandler>("GrantManagementRevoke")
            .AddSingleton<IEndpointModule, GrantManagementEndpointModule>()
            .AddScoped<IRequestHandler<GrantManagementRequest, Unit>, GrantManagementRevokeRequestHandler>()
            .AddScoped<IRequestValidator<GrantManagementRequest, GrantManagementValidatedRequest>, GrantManagementRequestValidator>()
            .AddScoped<IRequestProcessor<GrantManagementValidatedRequest, Unit>, GrantManagementRevokeRequestProcessor>()
    }
}