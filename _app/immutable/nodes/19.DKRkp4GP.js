import{f as h,a as e,t as l}from"../chunks/BHF9wNqu.js";import"../chunks/CU9afjlv.js";import{f as A,e as E,s as t,$ as D,n as s}from"../chunks/DL6eumzt.js";import{h as z}from"../chunks/DMOXgEdX.js";import{C as p}from"../chunks/DbZgjyKz.js";import{I as w}from"../chunks/CuMYCe1t.js";import{P as O,S as m}from"../chunks/C3UgRdqy.js";var U=h(`<p>The following sections describe how to setup AuthServer framework in
        your solution. <br/> The example code is written for an AspNetCore WebApp in .NET 10. <br/> If you don't want to read the setup documentation, but just want to head directly into the code,
        then take a look at the MVP setup in <a href="https://github.com/jokk-itu/authserver-framework/tree/main/src/AuthServer.TestIdentityProvider">AuthServer.TestIdentityProvider</a>.</p>`),G=h(`<p>The JwksDocument is responsible for defining keys for signing and
        encrypting tokens.</p> <!> <!> <p>The DiscoveryDocument is responsible for defining metadata about your
        AuthServer instance. It is only customizable properties that are
        exposed, as some are internally handled.</p> <!> <p>The UserInteraction is responsible for defining URL's for AuthServer to
        redirect to, when processing OpenId Connect requests. For example, when
        redirecting from the authorize endpoint or the end-session endpoint.</p> <!> <p>If your deployment is distributed, such that you have multiple deployments of AuthServer, then it is important to handle clock drifting.
        This is important as creating tokens and verifying tokens can happen on different machines.
        The token validation can be customized to allow a ClockSkew of a custom TimeSpan.</p> <!> <p>Endpoints can be customized using the EndpointOptions.
        For example, to require authentication for POST in the register endpoint.</p> <!>`,1),B=h(`<p>The modules in AuthServer are built to be dynamically turned on or off
        during runtime. This is handled through the library
        Microsoft.FeatureManagement.</p> <!>`,1),N=h(`<p>Some tables can grow very large over time, and it is therefore important to cleanup rows that cannot be used anymore.
        There exist BackgroundServices to automatically cleanup rows for Session, AuthorizationGrant and Token tables.
        Rows being deleted are only revoked or expired.
        These services can be configured using the following options fields.</p> <!>`,1),M=h(`<b>AuthServer.Cache.Abstractions.IDistributedCache</b> <p>Its purpose is to act as a distributed cache for multi instance deployments.
        If you only have a single instance, then an in-memory cache implementation is sufficient.
        The cache only contains keys and values.</p> <p>An implementation is required for the interface, as the cache is a core component of the framework.</p> <p>An example implementation using Redis.StackExchange can be seen below.</p> <!> <br/> <b>AuthServer.Authentication.Abstractions.IUserClaimService</b> <p>Its purpose is to return end user's claims, such that they can be used in tokens and at the userinfo endpoint.
        This should connect to your datastore, where you persist information about end users.</p> <p>An implementation is required if end users are supported in your custom AuthServer implementation.</p> <br/> <b>AuthServer.Authentication.Abstractions.IAuthenticatedUserAccessor</b> <p>Its purpose is to provide access to currently authenticated identities, in the user's browser.
        This is needed to determine if SSO can be performed, or if the user must choose which identity to login with.
        This can be implemented using the cookie authentication handler provided through AspNet.Core.</p> <p>An implementation is required if end users are supported in your custom AuthServer implementation.</p> <br/> <b>AuthServer.Authorize.Abstractions.IAuthenticationContextReferenceResolver</b> <p>Its purpose is to return an AuthenticationContextReference from an AuthenticationMethodReference.</p> <br/> <b>AuthServer.TokenByGrant.TokenExchangeGrant.Abstractions.IExtendedTokenExchangeRequestValidator</b> <p>Its purpose is to allow for customizing validation during token exchange grant type at the token endpoint.</p>`,1),V=h(`<p>The following example shows how to add services for AuthServer, and how
        to setup AuthServer in the AspNetCore HTTP request pipeline.</p> <!>`,1),q=h("<p>Remember to change the ClientUri to your deployment URL.</p>"),K=h(`<p>Once migrations have been created and applied to the database, the
        initial data must be added.</p> <br/> <p>AuthenticationContextReferences must be added. The following example
        inserts a single row in the AuthenticationContextReference table.</p> <!> <p>The IdentityProvider must be added. The following example inserts
        AuthServer as a client, and authorizes AuthServer to receive tokens with
        scopes.</p> <!> <!> <p>Custom Scopes can be added. The following example inserts a single row
        in the Scope table.</p> <!>`,1),L=h(`<p>There are heplful services in the framework, which can be used to make authorization grants and consent, used during end user authentication.
        For example, during authorize of the authorization_code grant type or during redeeming the user code of device_code grant type.</p> <p>The following interfaces can be injected and used. They all exist in the namespace AuthServer.UserInterface.Abstractions.</p> <ul><li>IAuthorizationCodeGrantService</li> <li>IAuthorizeService</li> <li>IConsentGrantService</li> <li>IDeviceAuthorizeService</li> <li>IDeviceCodeGrantService</li> <li>IEndSessionService</li></ul>`,1),W=h("<!> <!> <!> <!> <!> <!> <!> <!> <!>",1);function Z(R){var b=W();z("qwvjmj",o=>{E(()=>{D.title="IdentityProvider setup overview"})});var C=A(b);O(C,{title:"Setup"});var $=t(C,2);m($,{title:"Introduction",children:(o,g)=>{var r=U();e(o,r)},$$slots:{default:!0}});var T=t($,2);m(T,{title:"Options",children:(o,g)=>{var r=G(),u=t(A(r),2);w(u,{children:(n,S)=>{s();var a=l("There must only be registered one key per algorithm. The algorithm is set in the constructor of the key.");e(n,a)},$$slots:{default:!0}});var d=t(u,2);p(d,{children:(n,S)=>{s();var a=l();a.nodeValue=`
// Inside Program.cs
using AuthServer.Options;
using AuthServer.Enums;
                            
var builder = WebApplication.CreateBuilder(args);
var rsa = RSA.Create(3072);
var rsaSecurityKey = new RsaSecurityKey(rsa)
{
  KeyId = Guid.NewGuid().ToString();
};
builder.Services
    .AddOptions<JwksDocument>()
    .Configure(options =>
    {
        options.SigningKeys = [rsaSecurityKey, new SigningKey(SigningAlg.RsaSha256)];
        options.GetTokenSigningKey = () => options.SigningKeys.Single();
    });
`,e(n,a)},$$slots:{default:!0}});var v=t(d,4);p(v,{children:(n,S)=>{s();var a=l();a.nodeValue=`
// Inside Program.cs
using AuthServer.Options;
            
var builder = WebApplication.CreateBuilder(args);
builder.Services
    .AddOptions<DiscoveryDocument>()
    .Configure(options =>
    {
        options.Issuer = "https://idp.authserver.dk";
        options.ClaimsSupported = ["name", "address", "roles"];
        options.Scopes = ["openid", "profile"];
    });
`,e(n,a)},$$slots:{default:!0}});var i=t(v,4);p(i,{children:(n,S)=>{s();var a=l();a.nodeValue=`
// Inside Program.cs
using AuthServer.Options;
            
var builder = WebApplication.CreateBuilder(args);
builder.Services
    .AddOptions<UserInteraction>()
    .Configure(options =>
    {
        options.AccountSelectionUri = "https://idp.authserver.dk/select-account";
        options.ConsentUri = "https://idp.authserver.dk/consent";
        options.LoginUri = "https://idp.authserver.dk/login";
        options.EndSessionUri = "https://idp.authserver.dk/logout";
        options.VerificationUri = "https://idp.authserver.dk/device";
    });
`,e(n,a)},$$slots:{default:!0}});var c=t(i,4);p(c,{children:(n,S)=>{s();var a=l();a.nodeValue=`               
// Inside Program.cs
using AuthServer.Options;
            
var builder = WebApplication.CreateBuilder(args);
builder.Services
    .AddOptions<TokenValidationOptions>()
    .Configure(options =>
    {
        options.ClockSkew = TimeSpan.FromSeconds(10);
    });
`,e(n,a)},$$slots:{default:!0}});var f=t(c,4);p(f,{children:(n,S)=>{s();var a=l();a.nodeValue=`
// Inside Program.cs
using AuthServer.Options;

var builder = WebApplication.CreateBuilder(args);

// Setup your Authentication scheme

builder.Services
    .AddOptions<EndpointOptions>()
    .Configure(options =>
    {
        options.ClientRegistrationAuthenticationScheme = "NameOfAuthenticationScheme";
    });
`,e(n,a)},$$slots:{default:!0}}),e(o,r)},$$slots:{default:!0}});var y=t(T,2);m(y,{title:"Feature management",children:(o,g)=>{var r=B(),u=t(A(r),2);p(u,{children:(d,v)=>{s();var i=l();i.nodeValue=`
// Inside appsettings.json
{
  "FeatureManagement": {
    "TokenIntrospection": true,
    "TokenRevocation": true,
    "AuthorizationCode": true,
    "RefreshToken": true,
    "ClientCredentials": true,
    "DeviceCode": true,
    "TokenExchange": true
    "Userinfo": true,
    "GrantManagementRevoke": true,
    "GrantManagementQuery": true,
    "RegisterGet": true,
    "RegisterDelete": true,
    "RegisterPut": true,
    "RegisterPost": true,
    "EndSession": true,
    "PushedAuthorization": true,
    "Authorize": true,
    "DeviceAuthorization": true,
    "Discovery": true,
    "Jwks": true
  }
}
`,e(d,i)},$$slots:{default:!0}}),e(o,r)},$$slots:{default:!0}});var k=t(y,2);m(k,{title:"Automatic cleanup",children:(o,g)=>{var r=N(),u=t(A(r),2);p(u,{children:(d,v)=>{s();var i=l();i.nodeValue=`
// Inside Program.cs
using AuthServer.Options;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddOptions<CleanupOptions>(options =>
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
`,e(d,i)},$$slots:{default:!0}}),e(o,r)},$$slots:{default:!0}});var I=t(k,2);m(I,{title:"Interfaces",children:(o,g)=>{var r=M(),u=t(A(r),8);p(u,{children:(d,v)=>{s();var i=l();i.nodeValue=`
using AuthServer.Cache.Abstractions;
using System.Text.Json;

namespace CustomAuthServer.Cache;
public class DistributedCache : IDistributedCache
{
    private readonly ConnectionMultiplexer _connectionMultiplexer;

    // The ConnectionMultiplexer is setup in the DependencyInjection container
    public DistributedCache(ConnectionMultiplexer connectionMultiplexer)
    {
        _connectionMultiplexer = connectionMultiplexer;
    }

    public virtual Task<T?> Get<T>(string key, CancellationToken cancellationToken) where T : class
    {
        var database = _connectionMultiplexer.GetDatabase();
        return await database.StringGetAsync(key);
    }

    public virtual Task Add<T>(string key, T entity, DateTime? expiresOn, CancellationToken cancellationToken) where T : class
    {
        var database = _connectionMultiplexer.GetDatabase();
        await database.StringSetAsync(key, JsonSerializer.Serialize(entity));
    }

    public virtual Task Delete(string key, CancellationToken cancellationToken)
    {
        var database = _connectionMultiplexer.GetDatabase();
        await database.KeyDeleteAsync(key);
    }
}
        `,e(d,i)},$$slots:{default:!0}}),s(28),e(o,r)},$$slots:{default:!0}});var _=t(I,2);m(_,{title:"Startup",children:(o,g)=>{var r=V(),u=t(A(r),2);p(u,{children:(d,v)=>{s();var i=l();i.nodeValue=`
// Inside Program.cs
var builder = WebApplication.CreateBuilder(args);
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
        // Register the connection and migrations placement
        dbContextConfigurator.UseSqlServer(
            builder.Configuration.GetConnectionString("Default"),
            optionsBuilder =>
            {
                optionsBuilder.MigrationsAssembly("Custom.AuthServer.Assembly");
                optionsBuilder.UseQuerySplittingBehavior(QuerySplittingBehavior.SplitQuery);
            });
    });
            
var app = builder.Build();
            
// The invocation must occur after Authorization
app.UseAuthServer();
            
app.Run();
`,e(d,i)},$$slots:{default:!0}}),e(o,r)},$$slots:{default:!0}});var x=t(_,2);m(x,{title:"Database",children:(o,g)=>{var r=K(),u=t(A(r),6);p(u,{children:(c,f)=>{s();var n=l();n.nodeValue=`
INSERT INTO AuthenticationContextReference ([Name])
VALUES ('urn:authserver:loa:low')
        `,e(c,n)},$$slots:{default:!0}});var d=t(u,4);w(d,{children:(c,f)=>{var n=q();e(c,n)},$$slots:{default:!0}});var v=t(d,2);p(v,{children:(c,f)=>{s();var n=l();n.nodeValue=`
INSERT INTO Client (
  Id, [Name], ClientUri, ApplicationType, 
  TokenEndpointAuthMethod, TokenEndpointAuthSigningAlg,
  CreatedAt, AccessTokenExpiration, DPoPNonceExpiration, RequireConsent,
  RequirePushedAuthorizationRequests, RequireReferenceToken,
  RequireSignedRequestObject, RequireIdTokenClaims, RequireDPoPBoundAccessTokens)
VALUES (
  NEWID(), 'authserver', 'https://idp.authserver.dk',
  0, 0, 0, GETUTCDATE(), 0, 0, 0, 0, 0, 0, 0, 0)
           
DECLARE @ClientId UNIQUEIDENTIFIER = SCOPE_IDENTITY()
            
INSERT INTO ClientScope (ClientId, ScopeId)
VALUES
  (@ClientId, 7), -- authserver:userinfo
  (@ClientId, 9), -- grant_management_query
  (@ClientId, 10) -- grant_management_revoke
`,e(c,n)},$$slots:{default:!0}});var i=t(v,4);p(i,{children:(c,f)=>{s();var n=l();n.nodeValue=`
INSERT INTO Scope (Name)
VALUES ('value:of:custom:scope')
`,e(c,n)},$$slots:{default:!0}}),e(o,r)},$$slots:{default:!0}});var P=t(x,2);m(P,{title:"Authorization and Consent",children:(o,g)=>{var r=L();s(4),e(o,r)},$$slots:{default:!0}}),e(R,b)}export{Z as component};
