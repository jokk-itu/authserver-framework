<script lang="ts">
    import CodeBlock from "../../../components/CodeBlock.svelte";
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition("OAuth2.1", "https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/"), new RowCellDefinition("Core specification for OAuth") ],
        [ new RowCellDefinition("Resource Indicators for OAuth 2.0", "https://datatracker.ietf.org/doc/rfc8707/"), new RowCellDefinition("OAuth specification for resource parameter") ] 
    ];

    let requestHeaders: string[] = ["Name", "Description"];
    let requestRows: RowCellDefinition[][] = [
        [ new RowCellDefinition("grant_type"), new RowCellDefinition("Required. Must be equal to client_credentials.") ],
        [ new RowCellDefinition("scope"), new RowCellDefinition("Required. Space delimited scopes.") ],
        [ new RowCellDefinition("resource"), new RowCellDefinition("Required. URL of protected resource that is the audience of the access token.") ]
    ];

    let responseHeaders: string[] = ["Name", "Description"];
    let responseRows: RowCellDefinition[][] = [
        [ new RowCellDefinition("access_token"), new RowCellDefinition("The access token.") ],
        [ new RowCellDefinition("token_type"), new RowCellDefinition("The schema used in the Authorization HTTP header with the token, when requesting protected resources.") ],
        [ new RowCellDefinition("expires_in"), new RowCellDefinition("The amount of seconds until the token expires, from the issued time.") ],
        [ new RowCellDefinition("scope"), new RowCellDefinition("The scope the token is authorized for. It is equal to the request parameter.") ]
    ];
</script>

<PageTitle title="Client Credentials" />
<Section title="Introduction">
    <p>The grant type "client credentials" is used at the token endpoint, in exchange for an access_token.</p>
</Section>
<Section title="Specifications">
    <Table title="Specifications" tableNumber={1} headers={specificationHeaders} rowCellDefinitions={specificationRows} />
</Section>
<Section title="Token endpoint">
    <p>If the parameter "grant_type" is passed with value "client_credentials" to the token endpoint, then an access_token is returned.</p>
    <p>Only confidential clients are eligible for this grant type, as it requires client authentication.</p>
    <p>The following is an example HTTP request using client credentials and client_secret_basic as client authentication.</p>
    <CodeBlock>
        {`
POST /connect/token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=client_credentials
&scope=account:update%20account:delete
&resource=https%3A%2F%2Fapi-one.protectedresource.dk
&resource=https%3A%2F%2Fapi-two.protectedresource.dk
        `}
    </CodeBlock>
    <p>The following is an example HTTP response using client credentials.</p>
    <CodeBlock>
        {`
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-cache, no-store

{
  "access_token": "eyJhbGciO...ssw56c",
  "token_type": "Bearer",
  "expires_in": 500,
  "scope": "account:update account:delete"
}
        `}
    </CodeBlock>
    <p>The following table describes the request parameters. Client authentication parameters are not listed.</p>
    <Table title="Request parameters" tableNumber={1} headers={requestHeaders} rowCellDefinitions={requestRows} />
    <p>The following table describes the response parameters.</p>
    <Table title="Response parameters" tableNumber={2} headers={responseHeaders} rowCellDefinitions={responseRows} />
</Section>