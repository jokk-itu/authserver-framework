<script>
    import CodeBlock from "../../../components/CodeBlock.svelte";
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
</script>

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
                "Authorize": true,
                "AuthorizationCode": true,
                "PushedAuthorization": false
              }
            }
            `}
    </CodeBlock>
</Section>
<Section title="Interfaces">
    <p>
        Implement interface IDistibutedCache Implement interface
        IUserClaimService Implement interface IAuthenticatedUserAccessor
        Implement interface IAuthenticationContextReferenceResolver
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
    <p>AuthenticationContextReferences must be added.</p>
    <CodeBlock>
        {`
            INSERT INTO AuthenticationContextReference ([Name])
            VALUES ('urn:authserver:loa:low')
            `}
    </CodeBlock>
    <p>The IdentityProvider must be added.</p>
    <CodeBlock>
        {`
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
            `}
    </CodeBlock>
    <p>Custom Scopes must be added.</p>
    <CodeBlock>
        {`
            INSERT INTO Scope (Name)
            VALUES ('value:of:custom:scope')
            `}
    </CodeBlock>
</Section>
