<script lang="ts">
    import CodeBlock from "../../../components/CodeBlock.svelte";
    import InformationBanner from "../../../components/InformationBanner.svelte";
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('Token Introspection', 'https://datatracker.ietf.org/doc/html/rfc7662'), new RowCellDefinition('Specification for introspecting tokens') ]
    ];

    let requestHeaders: string[] = ["Name", "Description"];
    let requestFields: RowCellDefinition[][] = [
        [ new RowCellDefinition("token"), new RowCellDefinition("The token to be introspected. It is required.") ],
        [ new RowCellDefinition("token_type_hint"), new RowCellDefinition("The type of token to be introspected. It is optional.") ],
    ];

    let responseHeaders: string[] = ["Name", "Description"];
    let responseFields: RowCellDefinition[][] = [
        [ new RowCellDefinition("active"), new RowCellDefinition("Boolean determining if the token is active or not. This is required.") ],
        [ new RowCellDefinition("scope"), new RowCellDefinition("Space delimited string of scopes. This is optional.") ],
    ];
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
        The endpoint does not accept the 'none' client authentication method.
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
    <p>The following HTTP example shows a request to revoke an access token.</p> 
    <CodeBlock>
        {`
POST /connect/introspection HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

token=23nthgnreag67n
        `}
    </CodeBlock>
    <p>The following HTTP example shows the response.</p>
    <CodeBlock>
        {`
HTTP/1.1 200 BadRequest
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "": ""
}
        `}
    </CodeBlock>
</Section>