<script lang="ts">
    import { base } from "$app/paths";
    import CodeBlock from "../../../components/CodeBlock.svelte";
    import InformationBanner from "../../../components/InformationBanner.svelte";
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition("OpenId Connect RP-Initiated Logout", "https://openid.net/specs/openid-connect-rpinitiated-1_0.html"), new RowCellDefinition("Specification for the RP to logout at the IdP") ],
        [ new RowCellDefinition("OpenId Connect Backchannel Logout", "https://openid.net/specs/openid-connect-backchannel-1_0.html"), new RowCellDefinition("Specification for the IdP to logout clients") ],
        [ new RowCellDefinition("OpenId Connect Core", "https://openid.net/specs/openid-connect-core-1_0.html"), new RowCellDefinition("Core specification for OpenId Connect") ]
    ];

    let endSessionRequestHeaders: string[] = ["Name", "Description"];
    let endSessionRequestFields: RowCellDefinition[][] = [
        [ new RowCellDefinition("id_token_hint"), new RowCellDefinition("Id token belonging to the end user logging out. This is optional.") ],
        [ new RowCellDefinition("client_id"), new RowCellDefinition("ClientId of the client logging out on behalf of the end user. This is optional.") ],
        [ new RowCellDefinition("post_logout_redirect_uri"), new RowCellDefinition("URI to redirect to after logging out. This is optional.") ],
        [ new RowCellDefinition("state"), new RowCellDefinition("State parameter used with the redirect URI to mitigate CSRF attacks. This is required if redirect uri is provided.") ]
    ];

    let backchannelLogoutRequestHeaders: string[] = ["Name", "Description"];
    let backchannelLogoutRequestFields: RowCellDefinition[][] = [
        [ new RowCellDefinition("logout_token"), new RowCellDefinition("JWT containing claims about the end user being logged out.") ]
    ];

    let logoutTokenHeaders: string[] = ["Name", "Description"];
    let logoutTokenFields: RowCellDefinition[][] = [
        [ new RowCellDefinition("iss"), new RowCellDefinition("URI of AuthServer, as defined in the discovery document. This is required.") ],
        [ new RowCellDefinition("sub"), new RowCellDefinition("End user identifier. This is required if sid is not provided.") ],
        [ new RowCellDefinition("aud"), new RowCellDefinition("Client identifier. This is required.") ],
        [ new RowCellDefinition("iat"), new RowCellDefinition("Time of token issuance. This is required.") ],
        [ new RowCellDefinition("exp"), new RowCellDefinition("Time of token expiration. This is required.") ],
        [ new RowCellDefinition("jti"), new RowCellDefinition("Token identifier. This is required.") ],
        [ new RowCellDefinition("sid"), new RowCellDefinition("Session identifier. This is required if sub is not provided.") ],
        [ new RowCellDefinition("typ"), new RowCellDefinition("Type of JsonWebToken. This is a required header and must be logout+jwt.") ],
        [ new RowCellDefinition("events"), new RowCellDefinition("JSON object, with field http://schemas.openid.net/event/backchannel-logout. This is a required.") ]
    ];
</script>

<svelte:head>
	<title>RP-Initiated Logout</title>
</svelte:head>

<PageTitle title="RP-Initiated Logout" />
<Section title="Introduction">
    <p>
        The client (or relying party RP) can initiate logout at the IdP through an end session endpoint.
        The flow can logout the end user of the initiating client, or end the session at the IdP, and logging out all clients on the session of the end user.
    </p>
    <p>
        The logout of all clients is done through backchannel logout from the IdP.
    </p>
    <br>
    <p>
        The following image shows the logout flow, from logout at the client, to backchannel logout at the identity provider.
    </p>
    <br>
    <figure>
        <img class="mx-auto" src="{base}/rp-initiated-logout.png" alt="rp-initiated logout flow" />
        <figCaption class="text-center">Image 1: RP-Initiated Logout flow</figCaption>
    </figure>
</Section>
<Section title="Specifications">
    <Table title="Specifications" tableNumber={1} headers={specificationHeaders} rowCellDefinitions={specificationRows} />
</Section>
<Section title="End session endpoint">
    <p>
        Once the client has initiated the logout flow, the client redirects to the identity provider "end-session" endpoint.
    </p>
    <p>
        The identity provider then provides a page for the end-user to let the user either continue logging out from the client, or continue a single sign out flow.
    </p>
    <p>
        The single sign out flow differs by initiating a backchannel logout request to all clients with grants in the end-user's session.
        Whereas only logging out from the initiating client, requests backchannel logout to that client, and the session is not revoked.
    </p>
    <br>
    <InformationBanner>
        <p>The page being displayed for the end-user is custom and defined at the LogoutUri.</p>
    </InformationBanner>
    <br>
    <p>
        The request parameters for the end session endpoint are described in table 2.
    </p>
    <br>
    <Table title="End session request fields" tableNumber={2} headers={endSessionRequestHeaders} rowCellDefinitions={endSessionRequestFields} />
    <br>
    <p>
        The following HTTP example shows an end-session request.
    </p>
    <CodeBlock>
{`
GET /connect/end-session?id_token_hint=eybjsdvbb HTTP/1.1
Host: idp.authserver.dk
`}
    </CodeBlock>
    <br>
    <p>
        The following HTTP example shows an end-session response, redirecting to the LogoutUri.
    </p>
        <CodeBlock>
{`
HTTP/1.1 303 SeeOther
Location: https://idp.authserver.dk/SignOut
Cache-Control: no-cache, no-store
`}
    </CodeBlock>
    <br>
    <p>
        The following HTTP example shows an end-session response, redirecting to the PostLogoutRedirectUri.
    </p>
    <CodeBlock>
{`
HTTP/1.1 303 SeeOther
Location: https://app.example.com/logout-callback?state=narfojdobnob
Cache-Control: no-cache, no-store
`}
    </CodeBlock>
</Section>
<Section title="Backchannel logout endpoint">
    <p>
        Once the end user has logged out, a request is sent from the IdP to the client logging out on behalf of the end user, and optionally all clients participating in the session.
    </p>
    <br>
    <p>
        The request parameters for the backchannel logout endpoint are described in table 3.
    </p>
    <br>
    <Table title="Backchannel logout request fields" tableNumber={3} headers={backchannelLogoutRequestHeaders} rowCellDefinitions={backchannelLogoutRequestFields} />
    <br>
    <p>
        The following HTTP example shows a backchannel logout request to a client.
    </p>
    <p>
        The endpoint is defined by the client, through their client metadata.
        The endpoint must accept the POST method, and the body content type is "application/x-www-form-urlencoded".
    </p>
    <br>
    <CodeBlock>
{`
POST /backchannel-logout HTTP/1.1
Host: app.example.com
Content-Type: application/x-www-form-urlencoded

logout_token=eyascdiuvbiuv
`}
    </CodeBlock>
    <br>
    <p>
        The following HTTP example shows a backchannel logout response.
    </p>
    <br>
    <CodeBlock>
{`
HTTP/1.1 200 Ok
`}
    </CodeBlock>
</Section>
<Section title="Logout token">
    <p>
        The logout token is a structured JWT and is signed the same as an Id token.
        It can optionally be encrypted the same as an Id token.
        The behaviour is defined by the client metadata for id tokens.
    </p>
    <p>The token contains the fields defined in table 4.</p>
    <br>
    <Table title="Logout token fields" tableNumber={4} headers={logoutTokenHeaders} rowCellDefinitions={logoutTokenFields} />
    <br>
    <InformationBanner>
        <p>
            The token must contain a sid or sub claim, and optionally it can contain both.
        </p>
    </InformationBanner>
    <br>
    <p>The following JSON example shows a base64 decoded logout token sent to a backchannel logout endpoint.</p>
    <p>The signature block is omitted.</p>
    <CodeBlock>
{`
{
  "typ": "logout+jwt",
  "alg": "ES256"
}
.
{
  "iss": "https://idp.authserver.dk",
  "sub": "527deb3f-ea48-46c5-bb94-4d267a080fa7",
  "sid": "2a105f5a-06fc-4c5b-ba92-88ac2524b44b",
  "aud": "16a5c393-0084-4e2b-a538-f1c8a50b6161",
  "iat": 1471566154,
  "exp": 1471569754,
  "jti": "2c91dc13-6c7b-4dff-9f1c-e10c48bc549c",
  "events": {
    "http://schemas.openid.net/event/backchannel-logout"
  }
}
`}
    </CodeBlock>
</Section>