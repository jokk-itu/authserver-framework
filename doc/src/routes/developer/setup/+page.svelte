<script>
    import CodeBlock from "../../../components/CodeBlock.svelte";
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
</script>

<svelte:head>
    <title>IdentityProvider setup overview</title>
</svelte:head>

<PageTitle title="Setup" />
<Section title="Introduction">
    <p>
        The following sections describe how to setup AuthServer framework in
        your solution.
        <br />
        The example code is written for an AspNetCore WebApp in .NET 8.
    </p>
</Section>
<Section title="Options">
    <p>
        The JwksDocument is responsible for defining keys for signing and
        encrypting tokens. There must only be registered one key per algorithm.
    </p>
    <CodeBlock>
{`
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
`}
    </CodeBlock>
    <p>
        The DiscoveryDocument is responsible for defining metadata about your
        AuthServer instance. It is only customizable properties that are
        exposed, as some are internally handled.
    </p>
    <CodeBlock>
{`
// Inside Program.cs
using AuthServer.Options;
            
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddOptions<DiscoveryDocument>(options =>
{
  options.Issuer = "https://idp.authserver.dk";
  options.ClaimsSupported = ["name", "address", "roles"];
  options.Scopes = ["openid", "profile"];
});
`}
    </CodeBlock>
    <p>
        The UserInteraction is responsible for defining URL's for AuthServer to
        redirect to, when processing OpenId Connect requests. For example, when
        redirecting from the authorize endpoint or the end-session endpoint.
    </p>
    <CodeBlock>
{`
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
`}
    </CodeBlock>
</Section>
<Section title="Feature management">
    <p>
        The modules in AuthServer are built to be dynamically turned on or off
        during runtime. This is handled through the library
        Microsoft.FeatureManagement.
    </p>
    <CodeBlock>
{`
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
`}
    </CodeBlock>
</Section>
<Section title="Automatic cleanup">
    <p>Some tables can grow very large over time, and it is therefore important to cleanup rows that cannot be used anymore.
        There exist BackgroundServices to automatically cleanup rows for Session, AuthorizationGrant and Token tables.
        Rows being deleted are only revoked or expired.
        These services can be configured using the following options fields.
    </p>
    <CodeBlock>
{`
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
`}
    </CodeBlock>
</Section>
<Section title="Interfaces">
    <p>The interface IDistributedCache in namespace AuthServer.Cache.Abstractions must be implemented.
        Its purpose is to act as a distributed cache for multi instance deployments.
        If you only have a single instance, then an in-memory cache implementation is sufficient.
        The cache only contains keys and values.
    </p>
    <br>
    <p>The interface IUserClaimService in namespace AuthServer.Authentication.Abstractions must be implemented.
        Its purpose is to return end user's claims, such that they can be used in tokens and at the userinfo endpoint.
        This should connect to your datastore, where you persist information about end users.
    </p>
    <br>
    <p>The interface IAuthenticatedUserAccessor in namespace AuthServer.Authentication.Abstractions must be implemented.
        Its purpose is to provide access to currently authenticated identities, in the user's browser.
        This is needed to determine if SSO can be performed, or if the user must choose which identity to login with.
        This can be implemented using the cookie authentication handler provided through AspNet.Core.
    </p>
    <br>
    <p>The interface IAuthenticationContextReferenceResolver in namespace AuthServer.Authorize.Abstractions must be implemented.
        Its purpose is to return a AuthenticationContextReference from an AuthenticationMethodReference.
    </p>
    <br>
    <p>The interface IExtendedTokenExchangeRequestValidator in namespace AuthServer.TokenByGrant.TokenExchangeGrant.Abstractions can be implemented.
        Its purpose is to extend validation during token exchange grant type at the token endpoint.
    </p>
</Section>
<Section title="Startup">
    <p>
        The following example shows how to add services for AuthServer, and how
        to setup AuthServer in the AspNetCore HTTP request pipeline.
    </p>
    <CodeBlock>
{`
// Inside Program.cs
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthServer();
            
var app = builder.Build();
            
// The invocation must occur after Authorization
app.UseAuthServer();
            
app.Run();
`}
    </CodeBlock>
</Section>
<Section title="Database">
    <p>
        Once migrations have been created and applied to the database, the
        initial data must be added.
    </p>
    <br />
    <p>
        AuthenticationContextReferences must be added. The following example
        inserts a single row in the AuthenticationContextReference table.
    </p>
    <CodeBlock>
        {`
INSERT INTO AuthenticationContextReference ([Name])
VALUES ('urn:authserver:loa:low')
        `}
    </CodeBlock>
    <p>
        The IdentityProvider must be added. The following example inserts
        AuthServer as a client, and authorizes AuthServer to receive tokens with
        scopes.
    </p>
    <CodeBlock>
{`
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
`}
    </CodeBlock>
    <p>
        Custom Scopes must be added. The following example inserts a single row
        in the Scope table.
    </p>
    <CodeBlock>
{`
INSERT INTO Scope (Name)
VALUES ('value:of:custom:scope')
`}
    </CodeBlock>
</Section>
