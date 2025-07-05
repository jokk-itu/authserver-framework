<script lang="ts">
    import CodeBlock from "../../../components/CodeBlock.svelte";
    import InformationBanner from "../../../components/InformationBanner.svelte";
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('OpenId Connect', 'https://openid.net/specs/openid-connect-core-1_0.html'), new RowCellDefinition('Core specification for OpenId Connect') ],
        [ new RowCellDefinition('Token Introspection', 'https://datatracker.ietf.org/doc/html/rfc7662'), new RowCellDefinition('Specification for introspecting tokens') ],
        [ new RowCellDefinition("DPoP", "https://datatracker.ietf.org/doc/html/rfc9449"), new RowCellDefinition("Specification for sender constraining tokens using DPoP") ],
        [ new RowCellDefinition('Step up authentication', 'https://datatracker.ietf.org/doc/html/rfc9470/'), new RowCellDefinition('Step up authentication specification') ]
    ];

    let requestHeaders: string[] = ["Name", "Description"];
    let requestFields: RowCellDefinition[][] = [
        [ new RowCellDefinition("token"), new RowCellDefinition("The token to be introspected. It is required.") ],
        [ new RowCellDefinition("token_type_hint"), new RowCellDefinition("The type of token to be introspected. It is optional.") ],
    ];

    let responseHeaders: string[] = ["Name", "Description"];
    let responseFields: RowCellDefinition[][] = [
        [ new RowCellDefinition("active"), new RowCellDefinition("Boolean determining if the token is active or not. This is required.") ],
        [ new RowCellDefinition("scope"), new RowCellDefinition("Space delimited string of scopes. This is required if active.") ],
        [ new RowCellDefinition("client_id"), new RowCellDefinition("Id of client that owns the token. This is required if active.") ],
        [ new RowCellDefinition("username"), new RowCellDefinition("Username of the token's subject. This is optional.") ],
        [ new RowCellDefinition("token_type"), new RowCellDefinition("The token's type, which is either Bearer or DPoP. This is required if active.") ],
        [ new RowCellDefinition("exp"), new RowCellDefinition("Unix timestamp when the token expires. This is required if active.") ],
        [ new RowCellDefinition("iat"), new RowCellDefinition("Unix timestamp when the token was issued. This is required if active.") ],
        [ new RowCellDefinition("nbf"), new RowCellDefinition("Unix timestamp when the token is active from. This is required if active.") ],
        [ new RowCellDefinition("sub"), new RowCellDefinition("Subject of the token. Either the end-user or the client. This is required if active.") ],
        [ new RowCellDefinition("aud"), new RowCellDefinition("Array of URIs that may accept the token. This is required if active.") ],
        [ new RowCellDefinition("iss"), new RowCellDefinition("URI of AuthServer. This is required if active.") ],
        [ new RowCellDefinition("jti"), new RowCellDefinition("Unique identifier of the token. This is required if active.") ],
        [ new RowCellDefinition("auth_time"), new RowCellDefinition("Unix timestamp of when the end-user authenticated. This is optional.") ],
        [ new RowCellDefinition("acr"), new RowCellDefinition("The AuthenticationContextReference used when the end-user authenticated. This is optional.") ],
        [ new RowCellDefinition("cnf"), new RowCellDefinition("Object with one field, which is jkt. That is the thumbprint of the DPoP if the token is sender-constrained. This is optional.") ],
        [ new RowCellDefinition("access_control"), new RowCellDefinition("Object with end-user claims used for authorization purposes. This is optional.") ],
    ]
</script>

<svelte:head>
	<title>Token Introspection Endpoint</title>
</svelte:head>

<PageTitle title="Token Introspection" />
<Section title="Introduction">
    <p>
        The token introspection endpoint is used to introspect tokens.
        This is useful when the client requires opaque tokens that are not structured,
        such that protected resources can request the introspection endpoint and get information about the token.
        The endpoint supports introspecting access tokens and refresh tokens.
    </p>
</Section>
<Section title="Specifications">
    <Table title="Specifications" tableNumber={1} headers={specificationHeaders} rowCellDefinitions={specificationRows} />
</Section>
<Section title="Token Introspection Endpoint">
    <p>The token introspection endpoint accepts the POST HTTP method, and the content is application/x-www-form-urlencoded.</p>
    <p>The endpoint also requires client authentication, and the parameters are defined in the Client Authentication page.</p>
    <InformationBanner>
        The endpoint requires client authentication by confidential clients.
    </InformationBanner>
    <br>
    <p>The token introspection endpoint returns HTTP 200 if successful, and 400 if an error occurred.</p>
    <InformationBanner>
        If the token does not exist, is revoked, expired then the token is deemed inactive.
        If the client is not authorized for any scope of the token,
        or if the client is not an audience of the token, then the token is deemed inactive.
    </InformationBanner>
    <br>
    <p>The following table shows the parameters that can be sent to the endpoint.</p>
    <Table title="Token Introspection request parameters" tableNumber={2} headers={requestHeaders} rowCellDefinitions={requestFields} />
    <br>
    <Table title="Token Introspection response parameters" tableNumber={3} headers={responseHeaders} rowCellDefinitions={responseFields} />
    <br>
    <p>The following HTTP example shows a request to introspect an access token.</p> 
    <CodeBlock>
        {`
POST /connect/introspection HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

token=23nthgnreag67n
        `}
    </CodeBlock>
    <p>The following HTTP example shows a response with an active dpop bound token and an end-user as the subject.</p>
    <CodeBlock>
        {`
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "active": true,
  "scope": "scope:read scope:write",
  "client_id": "35d7d4f0-27c8-463c-8057-d39953a16972",
  "username": "john",
  "token_type": "DPoP",
  "exp": 1751708358,
  "iat": 1751708058,
  "nbf": 1751708058,
  "sub": "ec14d771-d1bb-4d0c-9965-8243700a739f",
  "aud": [ "https://api.authserver.dk" ],
  "iss": "https://idp.authserver.dk",
  "jti": "ec26ea37-e612-45f7-8989-612554499117",
  "auth_time": 1751707358,
  "acr": "urn:authserver:loa:substantial",
  "cnf":
  {
    "jkt": "ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
  },
  "access_control":
  {
    "roles": [ "admin" ]
  }
}
        `}
    </CodeBlock>
    <p>The following HTTP example shows a response with an active bearer token and the client as the subject.</p>
    <CodeBlock>
        {`
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "active": true,
  "scope": "scope:read scope:write",
  "client_id": "35d7d4f0-27c8-463c-8057-d39953a16972",
  "token_type": "Bearer",
  "exp": 1751708358,
  "iat": 1751708058,
  "nbf": 1751708058,
  "sub": "35d7d4f0-27c8-463c-8057-d39953a16972",
  "aud": [ "https://api.authserver.dk" ],
  "iss": "https://idp.authserver.dk",
  "jti": "ec26ea37-e612-45f7-8989-612554499117"
}
        `}
    </CodeBlock>
    <p>The following HTTP example shows a response with an inactive token.</p>
    <CodeBlock>
        {`
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "active": false
}
        `}
    </CodeBlock>
</Section>