<script lang="ts">
    import CodeBlock from "../../../components/CodeBlock.svelte";
    import InformationBanner from "../../../components/InformationBanner.svelte";
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('Token Revocation', 'https://datatracker.ietf.org/doc/html/rfc7009'), new RowCellDefinition('Specification for revoking tokens') ]
    ];

    let requestHeaders: string[] = ["Name", "Description"];
    let requestFields: RowCellDefinition[][] = [
        [ new RowCellDefinition("token"), new RowCellDefinition("The token to be revoked. It is required.") ],
        [ new RowCellDefinition("token_type_hint"), new RowCellDefinition("The type of token to be revoked. It is optional.") ],
    ];
</script>

<svelte:head>
	<title>Token Revocation Endpoint</title>
</svelte:head>

<PageTitle title="Token Revocation" />
<Section title="Introduction">
    <p>
        The token revocation endpoint is used to revoke tokens. This is useful when a client deems a token useless before it expires.
        The endpoint supports revoking access tokens and refresh tokens.
    </p>
</Section>
<Section title="Specifications">
    <Table title="Specifications" tableNumber={1} headers={specificationHeaders} rowCellDefinitions={specificationRows} />
</Section>
<Section title="Token Revocation Endpoint">
    <p>The token revocation endpoint accepts the POST HTTP method, and the content is application/x-www-form-urlencoded.</p>
    <p>The endpoint also requires client authentication, and the parameters are defined in the Client Authentication page.</p>
    <InformationBanner>
        The endpoint requires client authentication by confidential clients.
    </InformationBanner>
    <br>
    <p>The token revocation endpoint returns HTTP 200 with no content if successful, and 400 if an error occurred.</p>
    <InformationBanner>
        If the token is already revoked, expired or does not exist, then the operation is considered successful.
    </InformationBanner>
    <br>
    <p>The following table shows the parameters that can be sent to the endpoint.</p>
    <Table title="Token Revocation request parameters" tableNumber={2} headers={requestHeaders} rowCellDefinitions={requestFields} />
    <br>
    <p>The following HTTP example shows a request to revoke an access token.</p>
    <CodeBlock>
        {`
POST /connect/revoke HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

token=2YotnFZFEjr1zCsicMWpAA
        `}
    </CodeBlock>
    <p>The following HTTP example shows the response.</p>
    <CodeBlock>
        {`
HTTP/1.1 200 OK
Cache-Control: no-cache, no-store
        `}
    </CodeBlock>
</Section>