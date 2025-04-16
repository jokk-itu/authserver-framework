import{t as p,a as o,b as d}from"../chunks/BhbEvs11.js";import"../chunks/Cp21wPu0.js";import{f as g,s as n,n as l}from"../chunks/ANGeck7g.js";import{C as u}from"../chunks/D2PrUHZR.js";import{P as y,S as c}from"../chunks/Wq4Bs5Lt.js";var P=p(`<p>The following sections describe how to setup AuthServer framework in
        your solution. <br> The example code is written for an AspNetCore WebApp in .NET 8.</p>`),E=p(`<p>The JwksDocument is responsible for defining keys for signing and
        encrypting tokens. There must only be registered one key per algorithm.</p> <!> <p>The DiscoveryDocument is responsible for defining metadata about your
        AuthServer instance. It is only customizable properties that are
        exposed, as some are internally handled.</p> <!> <p>The UserInteraction is responsible for defining URL's for AuthServer to
        redirect to, when processing OpenId Connect requests. For example, when
        redirecting from the authorize endpoint or the end-session endpoint.</p> <!>`,1),R=p(`<p>The modules in AuthServer are built to be dynamically turned on or off
        during runtime. This is handled through the library
        Microsoft.FeatureManagement.</p> <!>`,1),k=p(`<p>Implement interface IDistibutedCache Implement interface
        IUserClaimService Implement interface IAuthenticatedUserAccessor
        Implement interface IAuthenticationContextReferenceResolver</p>`),x=p(`<p>The following example shows how to add services for AuthServer, and how
        to setup AuthServer in the AspNetCore HTTP request pipeline.</p> <!>`,1),N=p(`<p>Once migrations have been created and applied to the database, the
        initial data must be added.</p> <br> <p>AuthenticationContextReferences must be added.</p> <!> <p>The IdentityProvider must be added.</p> <!> <p>Custom Scopes must be added.</p> <!>`,1),U=p("<!> <!> <!> <!> <!> <!> <!>",1);function K(T){var f=U(),$=g(f);y($,{title:"Setup"});var S=n($,2);c(S,{title:"Introduction",children:(i,h)=>{var r=P();o(i,r)},$$slots:{default:!0}});var A=n(S,2);c(A,{title:"Options",children:(i,h)=>{var r=E(),s=n(g(r),2);u(s,{children:(e,m)=>{l();var t=d();t.nodeValue=`
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
        `,o(e,t)},$$slots:{default:!0}});var a=n(s,4);u(a,{children:(e,m)=>{l();var t=d();t.nodeValue=`
            // Inside Program.cs
            using AuthServer.Options;
            
            var builder = WebApplication.CreateBuilder(args);
            builder.Services.AddOptions<DiscoveryDocument>(options =>
            {
                options.Issuer = "https://idp.authserver.dk";
                options.ClaimsSupported = ["name", "address", "roles"];
                options.Scopes = ["openid", "profile"];
            });
            `,o(e,t)},$$slots:{default:!0}});var v=n(a,4);u(v,{children:(e,m)=>{l();var t=d();t.nodeValue=`
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
            `,o(e,t)},$$slots:{default:!0}}),o(i,r)},$$slots:{default:!0}});var I=n(A,2);c(I,{title:"Feature management",children:(i,h)=>{var r=R(),s=n(g(r),2);u(s,{children:(a,v)=>{l();var e=d();e.nodeValue=`
            // Inside appsettings.json
            {
              "FeatureManagement": {
                "Authorize": true,
                "AuthorizationCode": true,
                "PushedAuthorization": false
              }
            }
            `,o(a,e)},$$slots:{default:!0}}),o(i,r)},$$slots:{default:!0}});var _=n(I,2);c(_,{title:"Interfaces",children:(i,h)=>{var r=k();o(i,r)},$$slots:{default:!0}});var b=n(_,2);c(b,{title:"Startup",children:(i,h)=>{var r=x(),s=n(g(r),2);u(s,{children:(a,v)=>{l();var e=d();e.nodeValue=`
            // Inside Program.cs
            var builder = WebApplication.CreateBuilder(args);
            builder.Services.AddAuthServer();
            
            var app = builder.Build();
            
            // The invocation must occur after Authorization
            app.UseAuthServer();
            
            app.Run();
            `,o(a,e)},$$slots:{default:!0}}),o(i,r)},$$slots:{default:!0}});var C=n(b,2);c(C,{title:"Database",children:(i,h)=>{var r=N(),s=n(g(r),6);u(s,{children:(e,m)=>{l();var t=d();t.nodeValue=`
            INSERT INTO AuthenticationContextReference ([Name])
            VALUES ('urn:authserver:loa:low')
            `,o(e,t)},$$slots:{default:!0}});var a=n(s,4);u(a,{children:(e,m)=>{l();var t=d();t.nodeValue=`
            INSERT INTO Client (
                Id, [Name], ClientUri, ApplicationType, 
                TokenEndpointAuthMethod, TokenEndpointAuthSigningAlg,
                CreatedAt, AccessTokenExpiration, RequireConsent,
                RequirePushedAuthorizationRequests, RequireReferenceToken,
                RequireSignedRequestObject)
            VALUES (
                NEWID(), 'authserver', 'https://idp.authserver.dk',
                0, 0, 0, GETUTCDATE(), 0, 0, 0, 0, 0)
            
            DECLARE @ClientId UNIQUEIDENTIFIER = SCOPE_IDENTITY()
            
            INSERT INTO ClientScope (ClientId, ScopeId)
            VALUES
                (@ClientId, 7), -- authserver:userinfo
                (@ClientId, 9), -- grant_management_query
                (@ClientId, 10) -- grant_management_revoke
            `,o(e,t)},$$slots:{default:!0}});var v=n(a,4);u(v,{children:(e,m)=>{l();var t=d();t.nodeValue=`
            INSERT INTO Scope (Name)
            VALUES ('value:of:custom:scope')
            `,o(e,t)},$$slots:{default:!0}}),o(i,r)},$$slots:{default:!0}}),o(T,f)}export{K as component};
