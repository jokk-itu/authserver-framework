import{f as p,a as t,t as l}from"../chunks/BHF9wNqu.js";import"../chunks/CU9afjlv.js";import{f as h,e as _,s as o,$ as x,n as u}from"../chunks/DL6eumzt.js";import{h as w}from"../chunks/DMOXgEdX.js";import{C as d}from"../chunks/DbZgjyKz.js";import{P as R,S as v}from"../chunks/C3UgRdqy.js";var P=p(`<p>The following sections describe how to setup AuthServer framework in
        your solution. <br/> The example code is written for an AspNetCore WebApp in .NET 8.</p>`),E=p(`<p>The JwksDocument is responsible for defining keys for signing and
        encrypting tokens. There must only be registered one key per algorithm.</p> <!> <p>The DiscoveryDocument is responsible for defining metadata about your
        AuthServer instance. It is only customizable properties that are
        exposed, as some are internally handled.</p> <!> <p>The UserInteraction is responsible for defining URL's for AuthServer to
        redirect to, when processing OpenId Connect requests. For example, when
        redirecting from the authorize endpoint or the end-session endpoint.</p> <!>`,1),D=p(`<p>The modules in AuthServer are built to be dynamically turned on or off
        during runtime. This is handled through the library
        Microsoft.FeatureManagement.</p> <!>`,1),N=p(`<p>Some tables can grow very large over time, and it is therefore important to cleanup rows that cannot be used anymore.
        There exist BackgroundServices to automatically cleanup rows for Session, AuthorizationGrant and Token tables.
        Rows being deleted are only revoked or expired.
        These services can be configured using the following options fields.</p> <!>`,1),z=p(`<b>AuthServer.Cache.Abstractions.IDistributedCache</b> <p>Its purpose is to act as a distributed cache for multi instance deployments.
        If you only have a single instance, then an in-memory cache implementation is sufficient.
        The cache only contains keys and values.</p> <p>An implementation is required for the interface, as the cache is a core component of the framework.</p> <p>An example implementation using Redis.StackExchange can be seen below.</p> <!> <br/> <b>AuthServer.Authentication.Abstractions.IUserClaimService</b> <p>Its purpose is to return end user's claims, such that they can be used in tokens and at the userinfo endpoint.
        This should connect to your datastore, where you persist information about end users.</p> <p>An implementation is required if end users are supported in your custom AuthServer implementation.</p> <br/> <b>AuthServer.Authentication.Abstractions.IAuthenticatedUserAccessor</b> <p>Its purpose is to provide access to currently authenticated identities, in the user's browser.
        This is needed to determine if SSO can be performed, or if the user must choose which identity to login with.
        This can be implemented using the cookie authentication handler provided through AspNet.Core.</p> <p>An implementation is required if end users are supported in your custom AuthServer implementation.</p> <br/> <b>AuthServer.Authorize.Abstractions.IAuthenticationContextReferenceResolver</b> <p>Its purpose is to return an AuthenticationContextReference from an AuthenticationMethodReference.</p> <br/> <b>AuthServer.TokenByGrant.TokenExchangeGrant.Abstractions.IExtendedTokenExchangeRequestValidator</b> <p>Its purpose is to allow for customizing validation during token exchange grant type at the token endpoint.</p>`,1),O=p(`<p>The following example shows how to add services for AuthServer, and how
        to setup AuthServer in the AspNetCore HTTP request pipeline.</p> <!>`,1),U=p(`<p>Once migrations have been created and applied to the database, the
        initial data must be added.</p> <br/> <p>AuthenticationContextReferences must be added. The following example
        inserts a single row in the AuthenticationContextReference table.</p> <!> <p>The IdentityProvider must be added. The following example inserts
        AuthServer as a client, and authorizes AuthServer to receive tokens with
        scopes.</p> <!> <p>Custom Scopes can be added. The following example inserts a single row
        in the Scope table.</p> <!>`,1),G=p("<!> <!> <!> <!> <!> <!> <!> <!>",1);function W(k){var f=G();w("qwvjmj",i=>{_(()=>{x.title="IdentityProvider setup overview"})});var b=h(f);R(b,{title:"Setup"});var A=o(b,2);v(A,{title:"Introduction",children:(i,m)=>{var n=P();t(i,n)},$$slots:{default:!0}});var S=o(A,2);v(S,{title:"Options",children:(i,m)=>{var n=E(),a=o(h(n),2);d(a,{children:(e,g)=>{u();var r=l();r.nodeValue=`
// Inside Program.cs
using AuthServer.Options;
using AuthServer.Enums;
                            
var builder = WebApplication.CreateBuilder(args);
var rsa = RSA.Create(3072);
var rsaSecurityKey = new RsaSecurityKey(rsa)
{
  KeyId = Guid.NewGuid().ToString();
};
builder.Services.AddOptions<JwksDocument>(options =>
{
  options.SigningKeys = [rsaSecurityKey, new SigningKey(SigningAlg.RsaSha256)];
  options.GetTokenSigningKey = () => options.SigningKeys.Single();
});
`,t(e,r)},$$slots:{default:!0}});var s=o(a,4);d(s,{children:(e,g)=>{u();var r=l();r.nodeValue=`
// Inside Program.cs
using AuthServer.Options;
            
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddOptions<DiscoveryDocument>(options =>
{
  options.Issuer = "https://idp.authserver.dk";
  options.ClaimsSupported = ["name", "address", "roles"];
  options.Scopes = ["openid", "profile"];
});
`,t(e,r)},$$slots:{default:!0}});var c=o(s,4);d(c,{children:(e,g)=>{u();var r=l();r.nodeValue=`
// Inside Program.cs
using AuthServer.Options;
            
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddOptions<UserInteraction>(options =>
{
  options.AccountSelectionUri = "https://idp.authserver.dk/select-account";
  options.ConsentUri = "https://idp.authserver.dk/consent";
  options.LoginUri = "https://idp.authserver.dk/login";
  options.EndSessionUri = "https://idp.authserver.dk/logout";
  options.VerificationUri = "https://idp.authserver.dk/device";
});
`,t(e,r)},$$slots:{default:!0}}),t(i,n)},$$slots:{default:!0}});var T=o(S,2);v(T,{title:"Feature management",children:(i,m)=>{var n=D(),a=o(h(n),2);d(a,{children:(s,c)=>{u();var e=l();e.nodeValue=`
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
`,t(s,e)},$$slots:{default:!0}}),t(i,n)},$$slots:{default:!0}});var $=o(T,2);v($,{title:"Automatic cleanup",children:(i,m)=>{var n=N(),a=o(h(n),2);d(a,{children:(s,c)=>{u();var e=l();e.nodeValue=`
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
`,t(s,e)},$$slots:{default:!0}}),t(i,n)},$$slots:{default:!0}});var y=o($,2);v(y,{title:"Interfaces",children:(i,m)=>{var n=z(),a=o(h(n),8);d(a,{children:(s,c)=>{u();var e=l();e.nodeValue=`
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
        `,t(s,e)},$$slots:{default:!0}}),u(28),t(i,n)},$$slots:{default:!0}});var C=o(y,2);v(C,{title:"Startup",children:(i,m)=>{var n=O(),a=o(h(n),2);d(a,{children:(s,c)=>{u();var e=l();e.nodeValue=`
// Inside Program.cs
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthServer();
            
var app = builder.Build();
            
// The invocation must occur after Authorization
app.UseAuthServer();
            
app.Run();
`,t(s,e)},$$slots:{default:!0}}),t(i,n)},$$slots:{default:!0}});var I=o(C,2);v(I,{title:"Database",children:(i,m)=>{var n=U(),a=o(h(n),6);d(a,{children:(e,g)=>{u();var r=l();r.nodeValue=`
INSERT INTO AuthenticationContextReference ([Name])
VALUES ('urn:authserver:loa:low')
        `,t(e,r)},$$slots:{default:!0}});var s=o(a,4);d(s,{children:(e,g)=>{u();var r=l();r.nodeValue=`
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
`,t(e,r)},$$slots:{default:!0}});var c=o(s,4);d(c,{children:(e,g)=>{u();var r=l();r.nodeValue=`
INSERT INTO Scope (Name)
VALUES ('value:of:custom:scope')
`,t(e,r)},$$slots:{default:!0}}),t(i,n)},$$slots:{default:!0}}),t(k,f)}export{W as component};
