using AuthServer.Authentication;
using AuthServer.Authentication.Abstractions;
using AuthServer.Authentication.OAuthToken;
using AuthServer.Authorization;
using AuthServer.Authorization.Abstractions;
using AuthServer.Authorization.OAuthToken;
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
using AuthServer.DeviceAuthorization;
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
using AuthServer.TokenByGrant.TokenAuthorizationCodeGrant;
using AuthServer.TokenByGrant.TokenClientCredentialsGrant;
using AuthServer.TokenByGrant.TokenDeviceCodeGrant;
using AuthServer.TokenByGrant.TokenExchangeGrant;
using AuthServer.TokenByGrant.TokenRefreshTokenGrant;
using AuthServer.TokenDecoders;
using AuthServer.TokenDecoders.Abstractions;
using AuthServer.Userinfo;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.FeatureManagement;
using Microsoft.IdentityModel.Tokens;

namespace AuthServer.Extensions;
public class AuthServerBuilder
{
    private readonly IServiceCollection _services;

    private bool _hasRegisteredTokenCoreServices;
    private bool _hasRegisteredGrantManagementCoreService;

    public AuthServerBuilder(IServiceCollection services)
    {
        _services = services;

        AddCoreServices();
        AddEncoders();
        AddClientServices();
        AddRepositories();
        AddOptions();
        AddAuthorization();
        AddTokenBuilders();
    }

    private void AddCoreServices()
    {
        _services.AddScopedFeatureManagement();
        _services.AddDataProtection();
        _services.AddSingleton<IMetricService, MetricService>();
        _services.AddScoped<IEndpointResolver, EndpointResolver>();
        _services.AddHttpContextAccessor();
    }

    private void AddEncoders()
    {
        _services
            .AddScoped<ITokenDecoder<ServerIssuedTokenDecodeArguments>, ServerIssuedTokenDecoder>()
            .AddScoped<ITokenDecoder<ClientIssuedTokenDecodeArguments>, ClientIssuedTokenDecoder>()
            .AddScoped<ICodeEncoder<EncodedAuthorizationCode>, CodeEncoder<EncodedAuthorizationCode>>()
            .AddScoped<ICodeEncoder<EncodedDeviceCode>, CodeEncoder<EncodedDeviceCode>>();
    }

    private void AddClientServices()
    {
        _services
            .AddScoped<IClientAuthenticationService, ClientAuthenticationService>()
            .AddScoped<IClientJwkService, ClientJwkService>()
            .AddScoped<IClientSectorService, ClientSectorService>()
            .AddScoped<IClientLogoutService, ClientLogoutService>()
            .AddScoped<ISecureRequestService, SecureRequestService>()
            .AddScoped<IDPoPService, DPoPService>();
    }

    private void AddRepositories()
    {
        _services
            .AddScoped<IClientRepository, ClientRepository>()
            .AddScoped<IConsentRepository, ConsentRepository>()
            .AddScoped<IAuthorizationGrantRepository, AuthorizationGrantRepository>()
            .AddScoped<ITokenRepository, TokenRepository>()
            .AddScoped<INonceRepository, NonceRepository>()
            .AddScoped<ISessionRepository, SessionRepository>()
            .AddScoped<IDeviceCodeRepository, DeviceCodeRepository>();
    }

    private void AddOptions()
    {
        _services
            .ConfigureOptions<PostConfigureDiscoveryDocumentOptions>()
            .ConfigureOptions<ValidateDiscoveryDocumentOptions>()
            .ConfigureOptions<ValidateJwksDocument>()
            .ConfigureOptions<ValidateUserInteractionOptions>();
    }

    private void AddAuthorization()
    {
        _services.AddScoped<IAuthorizationHandler, ScopeRequirementHandler>();
        _services
            .AddAuthorizationBuilder()
            .AddPolicy(AuthorizationConstants.Userinfo, new UserinfoPolicy())
            .AddPolicy(AuthorizationConstants.ClientManagement, new RegisterPolicy())
            .AddPolicy(AuthorizationConstants.GrantManagementQuery, new GrantManagementQueryPolicy())
            .AddPolicy(AuthorizationConstants.GrantManagementRevoke, new GrantManagementRevokePolicy());

        _services.AddScoped<IAuthorizationMiddlewareResultHandler, CustomAuthorizationMiddlewareResultHandler>();
        _services
            .AddAuthentication()
            .AddScheme<OAuthTokenAuthenticationOptions, OAuthTokenAuthenticationHandler>(
                OAuthTokenAuthenticationDefaults.AuthenticationScheme, null);
    }

    private void AddTokenBuilders()
    {
        _services
            .AddScoped<ITokenBuilder<LogoutTokenArguments>, LogoutTokenBuilder>()
            .AddScoped<ITokenBuilder<IdTokenArguments>, IdTokenBuilder>()
            .AddScoped<ITokenBuilder<ClientAccessTokenArguments>, ClientAccessTokenBuilder>()
            .AddScoped<ITokenBuilder<GrantAccessTokenArguments>, GrantAccessTokenBuilder>()
            .AddScoped<ITokenBuilder<RefreshTokenArguments>, RefreshTokenBuilder>()
            .AddScoped<ITokenBuilder<RegistrationTokenArguments>, RegistrationTokenBuilder>()
            .AddScoped<ITokenBuilder<UserinfoTokenArguments>, UserinfoTokenBuilder>()
            .AddScoped<ITokenSecurityService, TokenSecurityService>();
    }

    public AuthServerBuilder AddAuthorizationDbContext(
        Action<IServiceProvider, DbContextOptionsBuilder> databaseConfigurator)
    {
        _services
            .AddDbContext<AuthorizationDbContext>(databaseConfigurator)
            .AddScoped<IUnitOfWork, UnitOfWork>()
            .AddScoped<ICachedClientStore, CachedClientStore>()
            .AddScoped<ITokenReplayCache, TokenReplayCache>();

        return this;
    }

    /// <summary>
    /// HttpClient used for requesting client's request uri for JAR secured authorization.
    /// </summary>
    /// <param name="httpClientConfigurator"></param>
    /// <returns></returns>
    public AuthServerBuilder AddRequestHttpClient(Action<HttpClient>? httpClientConfigurator = null)
    {
        _services.AddHttpClient(HttpClientNameConstants.ClientRequest,
            httpClientConfigurator ?? (httpClient =>
            {
                httpClient.Timeout = TimeSpan.FromSeconds(2);
                httpClient.MaxResponseContentBufferSize = 1024 * 32;
            }));

        return this;
    }

    /// <summary>
    /// HttpClient used for requesting client's backchannel logout uri.
    /// </summary>
    /// <param name="httpClientConfigurator"></param>
    /// <returns></returns>
    public AuthServerBuilder AddLogoutHttpClient(Action<HttpClient>? httpClientConfigurator = null)
    {
        _services.AddHttpClient(HttpClientNameConstants.ClientLogout,
            httpClientConfigurator ?? (httpClient =>
            {
                httpClient.Timeout = TimeSpan.FromSeconds(2);
                httpClient.MaxResponseContentBufferSize = 1024 * 2;
            }));

        return this;
    }

    /// <summary>
    /// HttpClient used for requesting client's jwks uri.
    /// </summary>
    /// <param name="httpClientConfigurator"></param>
    /// <returns></returns>
    public AuthServerBuilder AddJwksHttpClient(Action<HttpClient>? httpClientConfigurator = null)
    {
        _services.AddHttpClient(HttpClientNameConstants.ClientJwks,
            httpClientConfigurator ?? (httpClient =>
            {
                httpClient.Timeout = TimeSpan.FromSeconds(2);
                httpClient.MaxResponseContentBufferSize = 1024 * 32;
            }));

        return this;
    }

    /// <summary>
    /// HttpClient used for requesting client's sector uri.
    /// </summary>
    /// <param name="httpClientConfigurator"></param>
    /// <returns></returns>
    public AuthServerBuilder AddSectorHttpClient(Action<HttpClient>? httpClientConfigurator = null)
    {
        _services.AddHttpClient(HttpClientNameConstants.ClientSector,
            httpClientConfigurator ?? (httpClient =>
            {
                httpClient.Timeout = TimeSpan.FromSeconds(2);
                httpClient.MaxResponseContentBufferSize = 1024 * 2;
            }));

        return this;
    }

    public AuthServerBuilder AddCleanupBackgroundServices()
    {
        _services
            .AddHostedService<SessionCleanupBackgroundService>()
            .AddHostedService<AuthorizationGrantCleanupBackgroundService>()
            .AddHostedService<TokenCleanupBackgroundService>();

        return this;
    }

    public AuthServerBuilder AddPushedAuthorization()
    {
        _services
            .AddKeyedScoped<IEndpointHandler, PushedAuthorizationEndpointHandler>(EndpointNameConstants.PushedAuthorization)
            .AddSingleton<IEndpointModule, PushedAuthorizationEndpointModule>()
            .AddScoped<IRequestAccessor<PushedAuthorizationRequest>, PushedAuthorizationRequestAccessor>()
            .AddScoped<IRequestHandler<PushedAuthorizationRequest, PushedAuthorizationResponse>, PushedAuthorizationRequestHandler>()
            .AddScoped<IRequestProcessor<PushedAuthorizationValidatedRequest, PushedAuthorizationResponse>, PushedAuthorizationRequestProcessor>()
            .AddScoped<IRequestValidator<PushedAuthorizationRequest, PushedAuthorizationValidatedRequest>, PushedAuthorizationRequestValidator>();

        return this;
    }

    public AuthServerBuilder AddRegister()
    {
        _services
            .AddScoped<IRequestAccessor<RegisterRequest>, RegisterRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, RegisterEndpointHandler>(EndpointNameConstants.Register)
            .AddSingleton<IEndpointModule, RegisterEndpointModule>()
            .AddScoped<IRequestHandler<RegisterRequest, ProcessResult<RegisterResponse, Unit>>, RegisterRequestHandler>()
            .AddScoped<IRequestValidator<RegisterRequest, RegisterValidatedRequest>, RegisterRequestValidator>()
            .AddScoped<IRequestProcessor<RegisterValidatedRequest, ProcessResult<RegisterResponse, Unit>>, RegisterRequestProcessor>();

        return this;
    }

    public AuthServerBuilder AddEndSession()
    {
        _services
            .AddScoped<IRequestAccessor<EndSessionRequest>, EndSessionRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, EndSessionEndpointHandler>(EndpointNameConstants.EndSession)
            .AddSingleton<IEndpointModule, EndSessionEndpointModule>()
            .AddScoped<IUserAccessor<EndSessionUser>, EndSessionUserAccessor>()
            .AddScoped<IRequestHandler<EndSessionRequest, Unit>, EndSessionRequestHandler>()
            .AddScoped<IRequestValidator<EndSessionRequest, EndSessionValidatedRequest>, EndSessionRequestValidator>()
            .AddScoped<IRequestProcessor<EndSessionValidatedRequest, Unit>, EndSessionRequestProcessor>()
            .AddScoped<IEndSessionService, EndSessionService>();

        return this;
    }

    public AuthServerBuilder AddUserinfo()
    {
        _services
            .AddScoped<IRequestAccessor<UserinfoRequest>, UserinfoRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, UserinfoEndpointHandler>(EndpointNameConstants.Userinfo)
            .AddSingleton<IEndpointModule, UserinfoEndpointModule>()
            .AddScoped<IRequestHandler<UserinfoRequest, string>, UserinfoRequestHandler>()
            .AddScoped<IRequestValidator<UserinfoRequest, UserinfoValidatedRequest>, UserinfoRequestValidator>()
            .AddScoped<IRequestProcessor<UserinfoValidatedRequest, string>, UserinfoRequestProcessor>();

        return this;
    }

    public AuthServerBuilder AddIntrospection()
    {
        _services
            .AddScoped<IRequestAccessor<IntrospectionRequest>, IntrospectionRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, IntrospectionEndpointHandler>(EndpointNameConstants.Introspection)
            .AddSingleton<IEndpointModule, IntrospectionEndpointModule>()
            .AddScoped<IRequestHandler<IntrospectionRequest, IntrospectionResponse>, IntrospectionRequestHandler>()
            .AddScoped<IRequestValidator<IntrospectionRequest, IntrospectionValidatedRequest>, IntrospectionRequestValidator>()
            .AddScoped<IRequestProcessor<IntrospectionValidatedRequest, IntrospectionResponse>, IntrospectionRequestProcessor>();

        return this;
    }

    public AuthServerBuilder AddRevocation()
    {
        _services
            .AddScoped<IRequestAccessor<RevocationRequest>, RevocationRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, RevocationEndpointHandler>(EndpointNameConstants.Revocation)
            .AddSingleton<IEndpointModule, RevocationEndpointModule>()
            .AddScoped<IRequestHandler<RevocationRequest, Unit>, RevocationRequestHandler>()
            .AddScoped<IRequestValidator<RevocationRequest, RevocationValidatedRequest>, RevocationRequestValidator>()
            .AddScoped<IRequestProcessor<RevocationValidatedRequest, Unit>, RevocationRequestProcessor>();

        return this;
    }

    public AuthServerBuilder AddAuthorizationCode()
    {
        AddToken();

        _services
            .AddScoped<IRequestAccessor<AuthorizeRequest>, AuthorizeRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, AuthorizeEndpointHandler>(EndpointNameConstants.Authorize)
            .AddSingleton<IEndpointModule, AuthorizeEndpointModule>()
            .AddScoped<IAuthorizeService, AuthorizeService>()
            .AddScoped<IAuthorizeInteractionService, AuthorizeInteractionService>()
            .AddScoped<IAuthorizeResponseBuilder, AuthorizeResponseBuilder>()
            .AddScoped<IUserAccessor<AuthorizeUser>, AuthorizeUserAccessor>()
            .AddScoped<IRequestHandler<AuthorizeRequest, AuthorizeResponse>, AuthorizeRequestHandler>()
            .AddScoped<IRequestProcessor<AuthorizeValidatedRequest, AuthorizeResponse>, AuthorizeRequestProcessor>()
            .AddScoped<IRequestValidator<AuthorizeRequest, AuthorizeValidatedRequest>, AuthorizeRequestValidator>();

        _services
            .AddKeyedScoped<IRequestHandler<TokenRequest, TokenResponse>, AuthorizationCodeRequestHandler>(GrantTypeConstants.AuthorizationCode)
            .AddScoped<IRequestProcessor<AuthorizationCodeValidatedRequest, TokenResponse>, AuthorizationCodeRequestProcessor>()
            .AddScoped<IRequestValidator<TokenRequest, AuthorizationCodeValidatedRequest>, AuthorizationCodeRequestValidator>();

        return this;
    }

    public AuthServerBuilder AddRefreshToken()
    {
        AddToken();

        _services
            .AddKeyedScoped<IRequestHandler<TokenRequest, TokenResponse>, RefreshTokenRequestHandler>(GrantTypeConstants.RefreshToken)
            .AddScoped<IRequestProcessor<RefreshTokenValidatedRequest, TokenResponse>, RefreshTokenRequestProcessor>()
            .AddScoped<IRequestValidator<TokenRequest, RefreshTokenValidatedRequest>, RefreshTokenRequestValidator>();

        return this;
    }

    public AuthServerBuilder AddClientCredentials()
    {
        AddToken();

        _services
            .AddKeyedScoped<IRequestHandler<TokenRequest, TokenResponse>, ClientCredentialsRequestHandler>(GrantTypeConstants.ClientCredentials)
            .AddScoped<IRequestProcessor<ClientCredentialsValidatedRequest, TokenResponse>, ClientCredentialsRequestProcessor>()
            .AddScoped<IRequestValidator<TokenRequest, ClientCredentialsValidatedRequest>, ClientCredentialsRequestValidator>();

        return this;
    }

    public AuthServerBuilder AddDeviceCode()
    {
        AddToken();

        _services
            .AddScoped<IRequestAccessor<DeviceAuthorizationRequest>, DeviceAuthorizationRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, DeviceAuthorizationEndpointHandler>(EndpointNameConstants.DeviceAuthorization)
            .AddScoped<IEndpointModule, DeviceAuthorizationEndpointModule>()
            .AddScoped<IRequestHandler<DeviceAuthorizationRequest, DeviceAuthorizationResponse>, DeviceAuthorizationRequestHandler>()
            .AddScoped<IRequestValidator<DeviceAuthorizationRequest, DeviceAuthorizationValidatedRequest>, DeviceAuthorizationRequestValidator>()
            .AddScoped<IRequestProcessor<DeviceAuthorizationValidatedRequest, DeviceAuthorizationResponse>, DeviceAuthorizationRequestProcessor>();

        _services
            .AddKeyedScoped<IRequestHandler<TokenRequest, TokenResponse>, DeviceCodeRequestHandler>(GrantTypeConstants.DeviceCode)
            .AddScoped<IRequestProcessor<DeviceCodeValidatedRequest, TokenResponse>, DeviceCodeRequestProcessor>()
            .AddScoped<IRequestValidator<TokenRequest, DeviceCodeValidatedRequest>, DeviceCodeRequestValidator>();

        return this;
    }

    public AuthServerBuilder AddTokenExchange()
    {
        AddToken();

        _services
            .AddKeyedScoped<IRequestHandler<TokenRequest, TokenResponse>, TokenExchangeRequestHandler>(GrantTypeConstants.TokenExchange)
            .AddScoped<IRequestProcessor<TokenExchangeValidationRequest, TokenResponse>, TokenExchangeRequestProcessor>()
            .AddScoped<IRequestValidator<TokenRequest, TokenExchangeValidationRequest>, TokenExchangeRequestValidator>();

        return this;
    }

    private void AddToken()
    {
        if (_hasRegisteredTokenCoreServices)
        {
            return;
        }

        _services
            .AddScoped<IRequestAccessor<TokenRequest>, TokenRequestAccessor>()
            .AddKeyedScoped<IEndpointHandler, TokenEndpointHandler>(EndpointNameConstants.Token)
            .AddSingleton<IEndpointModule, TokenEndpointModule>();

        _hasRegisteredTokenCoreServices = true;
    }

    public AuthServerBuilder AddGrantManagementRevoke()
    {
        AddGrantManagement();

        _services
            .AddKeyedScoped<IEndpointHandler, GrantManagementRevokeEndpointHandler>(EndpointNameConstants.GrantManagementRevoke)
            .AddSingleton<IEndpointModule, GrantManagementRevokeEndpointModule>()
            .AddScoped<IRequestHandler<GrantManagementRequest, Unit>, GrantManagementRevokeRequestHandler>()
            .AddScoped<IRequestProcessor<GrantManagementValidatedRequest, Unit>, GrantManagementRevokeRequestProcessor>();

        return this;
    }

    public AuthServerBuilder AddGrantManagementQuery()
    {
        AddGrantManagement();

        _services
            .AddKeyedScoped<IEndpointHandler, GrantManagementQueryEndpointHandler>(EndpointNameConstants.GrantManagementQuery)
            .AddSingleton<IEndpointModule, GrantManagementQueryEndpointModule>()
            .AddScoped<IRequestHandler<GrantManagementRequest, GrantResponse>, GrantManagementQueryRequestHandler>()
            .AddScoped<IRequestProcessor<GrantManagementValidatedRequest, GrantResponse>, GrantManagementQueryRequestProcessor>();

        return this;
    }

    private void AddGrantManagement()
    {
        if (_hasRegisteredGrantManagementCoreService)
        {
            return;
        }

        _services
            .AddScoped<IRequestAccessor<GrantManagementRequest>, GrantManagementRequestAccessor>();

        _hasRegisteredGrantManagementCoreService = true;
    }

    public AuthServerBuilder AddDiscovery()
    {
        _services
            .AddKeyedScoped<IEndpointHandler, DiscoveryEndpointHandler>(EndpointNameConstants.Discovery)
            .AddSingleton<IEndpointModule, DiscoveryEndpointModule>()
            .AddScoped<IRequestValidator<GrantManagementRequest, GrantManagementValidatedRequest>, GrantManagementRequestValidator>();

        return this;
    }

    public AuthServerBuilder AddJwks()
    {
        _services
            .AddKeyedScoped<IEndpointHandler, JwksEndpointHandler>(EndpointNameConstants.Jwks)
            .AddSingleton<IEndpointModule, JwksEndpointModule>();

        return this;
    }
}
