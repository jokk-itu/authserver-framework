<script lang="ts">
    import CodeBlock from "../../../components/CodeBlock.svelte";
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('OAuth2.1', 'https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/'), new RowCellDefinition('Core specification for OAuth') ],
        [ new RowCellDefinition('OpenId Connect', 'https://openid.net/specs/openid-connect-core-1_0.html'), new RowCellDefinition('Core specification for OpenId Connect') ]
    ];    
</script>

<svelte:head>
	<title>Refresh Token Grant</title>
</svelte:head>

<PageTitle title="Refresh Token" />
<Section title="Introduction">
    <p>When the client has received its initial access token,
        it can be efficient to refresh the token when it expires,
        or if the tokens scope or audience needs to be updated.
    </p>
    <p>
        The use case is covered by the refresh_token grant type,
        which exchanges a fresh access token by a refresh_token.
    </p>
    <br>
    <p>
        The refresh token typically has a longer lifetime than the access tokens,
        and can be defined in the client metadata.
    </p>
    <br>
    <p>
        If the refresh token request uses DPoP,
        and the client is public, then the refresh token must also be DPoP bound.
        It is recommended to sender-constraint the refresh token, instead of rotating refresh tokens.
    </p>    
</Section>
<Section title="Specifications">
    <Table title="Specifications" tableNumber={1} headers={specificationHeaders} rowCellDefinitions={specificationRows} />
</Section>
<Section title="Token Endpoint">
    <p>
        The request contains a refresh token from the initial token request,
        which returned the first token from another grant such as authorization_code.
    </p>
    <br>
    <p>
        It is possible to change the scope and audience of the access token,
        through the parameters "scope" and "resource".
    </p>
    <br>
    <p>The following HTTP example shows a token request using the code from the identity provider.</p>
    <CodeBlock>
        {`
POST /connect/token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=refresh_token
&refresh_token=SplxlOBeZQQYbYS6WxSbIA
&scope=weather:read
&resource=https%3A%2F%2Fapi-one.protectedresource.dk
`}
    </CodeBlock>
    <p>The following HTTP example shows a token response containing tokens exchanged from the refresh token.</p>
    <CodeBlock>
        {`
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "access_token":"2YotnFZFEjr1zCsicMWpAA",
  "token_type":"Bearer",
  "expires_in":3600,
  "scope":"weather:read",
  "id_token":"eyJhbGciOiJSUzI1NiIsImtpZCI...",
  "grant_id":"78FF77E8-F146-4F37-9C28-5FD0BC936980"
}
        `}
    </CodeBlock>
</Section>