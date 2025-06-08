import{t as p,h as R,a as n,b as d}from"../chunks/BdD32qd5.js";import"../chunks/BOyCDzPS.js";import{f as m,$ as k,s as o,n as u}from"../chunks/Db0b_LWK.js";import{C as l}from"../chunks/Dg6GzD5d.js";import{P,S as c}from"../chunks/DcIxqC40.js";var w=p(`<p>The following sections describe how to setup AuthServer framework in
        your solution. <br> The example code is written for an AspNetCore WebApp in .NET 8.</p>`),x=p(`<p>The JwksDocument is responsible for defining keys for signing and
        encrypting tokens. There must only be registered one key per algorithm.</p> <!> <p>The DiscoveryDocument is responsible for defining metadata about your
        AuthServer instance. It is only customizable properties that are
        exposed, as some are internally handled.</p> <!> <p>The UserInteraction is responsible for defining URL's for AuthServer to
        redirect to, when processing OpenId Connect requests. For example, when
        redirecting from the authorize endpoint or the end-session endpoint.</p> <!>`,1),E=p(`<p>The modules in AuthServer are built to be dynamically turned on or off
        during runtime. This is handled through the library
        Microsoft.FeatureManagement.</p> <!>`,1),N=p(`<p>Some tables can grow very large over time, and it is therefore important to cleanup rows that cannot be used anymore.
        There exist BackgroundServices to automatically cleanup rows for Session, AuthorizationGrant and Token tables.
        Rows being deleted are only revoked or expired.
        These services can be configured using the following options fields.</p> <!>`,1),O=p(`<p>The interface IDistributedCache in namespace AuthServer.Cache.Abstractions must be implemented.
        Its purpose is to act as a distributed cache for multi instance deployments.
        If you only have a single instance, then an in-memory cache implementation is sufficient.
        The cache only contains keys and values.</p> <p>The interface IUserClaimService in namespace AuthServer.Authentication.Abstractions must be implemented.
        Its purpose is to return end user's claims, such that they can be used in tokens and at the userinfo endpoint.
        This should connect to your datastore, where you persist information about end users.</p> <p>The interface IAuthenticatedUserAccessor in namespace AuthServer.Authentication.Abstractions must be implemented.
        Its purpose is to provide access to currently authenticated identities, in the user's browser.
        This is needed to determine if SSO can be performed, or if the user must choose which identity to login with.
        This can be implemented using the cookie authentication handler provided through AspNet.Core.</p> <p>The interface IAuthenticationContextReferenceResolver in namespace AuthServer.Authorize.Abstractions must be implemented.
        Its purpose is to return a AuthenticationContextReference from an AuthenticationMethodReference.</p>`,1),U=p(`<p>The following example shows how to add services for AuthServer, and how
        to setup AuthServer in the AspNetCore HTTP request pipeline.</p> <!>`,1),D=p(`<p>Once migrations have been created and applied to the database, the
        initial data must be added.</p> <br> <p>AuthenticationContextReferences must be added. The following example
        inserts a single row in the AuthenticationContextReference table.</p> <!> <p>The IdentityProvider must be added. The following example inserts
        AuthServer as a client, and authorizes AuthServer to receive tokens with
        scopes.</p> <!> <p>Custom Scopes must be added. The following example inserts a single row
        in the Scope table.</p> <!>`,1),z=p("<!> <!> <!> <!> <!> <!> <!> <!>",1);function L(y){var f=z();R(i=>{k.title="IdentityProvider setup overview"});var S=m(f);P(S,{title:"Setup"});var A=o(S,2);c(A,{title:"Introduction",children:(i,h)=>{var t=w();n(i,t)},$$slots:{default:!0}});var $=o(A,2);c($,{title:"Options",children:(i,h)=>{var t=x(),s=o(m(t),2);l(s,{children:(e,g)=>{u();var r=d();r.nodeValue=`
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
        `,n(e,r)},$$slots:{default:!0}});var a=o(s,4);l(a,{children:(e,g)=>{u();var r=d();r.nodeValue=`
            // Inside Program.cs
            using AuthServer.Options;
            
            var builder = WebApplication.CreateBuilder(args);
            builder.Services.AddOptions<DiscoveryDocument>(options =>
            {
                options.Issuer = "https://idp.authserver.dk";
                options.ClaimsSupported = ["name", "address", "roles"];
                options.Scopes = ["openid", "profile"];
            });
        `,n(e,r)},$$slots:{default:!0}});var v=o(a,4);l(v,{children:(e,g)=>{u();var r=d();r.nodeValue=`
            // Inside Program.cs
            using AuthServer.Options;
            
            var builder = WebApplication.CreateBuilder(args);
            builder.Services.AddOptions<UserInteraction>(options =>
            {
                options.AccountSelectionUri = "https://idp.authserver.dk/select-account";
                options.ConsentUri = "https://idp.authserver.dk/consent";
                options.LoginUri = "https://idp.authserver.dk/login";
                options.EndSessionUri = "https://idp.authserver.dk/logout";
            });
        `,n(e,r)},$$slots:{default:!0}}),n(i,t)},$$slots:{default:!0}});var b=o($,2);c(b,{title:"Feature management",children:(i,h)=>{var t=E(),s=o(m(t),2);l(s,{children:(a,v)=>{u();var e=d();e.nodeValue=`
            // Inside appsettings.json
            {
              "FeatureManagement": {
                "TokenIntrospection": true,
                "TokenRevocation": true,
                "AuthorizationCode": true,
                "RefreshToken": true,
                "ClientCredentials": true,
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
                "Discovery": true,
                "Jwks": true
              }
            }
        `,n(a,e)},$$slots:{default:!0}}),n(i,t)},$$slots:{default:!0}});var T=o(b,2);c(T,{title:"Automatic cleanup",children:(i,h)=>{var t=N(),s=o(m(t),2);l(s,{children:(a,v)=>{u();var e=d();e.nodeValue=`
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
        `,n(a,e)},$$slots:{default:!0}}),n(i,t)},$$slots:{default:!0}});var I=o(T,2);c(I,{title:"Interfaces",children:(i,h)=>{var t=O();u(6),n(i,t)},$$slots:{default:!0}});var C=o(I,2);c(C,{title:"Startup",children:(i,h)=>{var t=U(),s=o(m(t),2);l(s,{children:(a,v)=>{u();var e=d();e.nodeValue=`
            // Inside Program.cs
            var builder = WebApplication.CreateBuilder(args);
            builder.Services.AddAuthServer();
            
            var app = builder.Build();
            
            // The invocation must occur after Authorization
            app.UseAuthServer();
            
            app.Run();
        `,n(a,e)},$$slots:{default:!0}}),n(i,t)},$$slots:{default:!0}});var _=o(C,2);c(_,{title:"Database",children:(i,h)=>{var t=D(),s=o(m(t),6);l(s,{children:(e,g)=>{u();var r=d();r.nodeValue=`
            INSERT INTO AuthenticationContextReference ([Name])
            VALUES ('urn:authserver:loa:low')
        `,n(e,r)},$$slots:{default:!0}});var a=o(s,4);l(a,{children:(e,g)=>{u();var r=d();r.nodeValue=`
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
        `,n(e,r)},$$slots:{default:!0}});var v=o(a,4);l(v,{children:(e,g)=>{u();var r=d();r.nodeValue=`
            INSERT INTO Scope (Name)
            VALUES ('value:of:custom:scope')
        `,n(e,r)},$$slots:{default:!0}}),n(i,t)},$$slots:{default:!0}}),n(y,f)}export{L as component};
