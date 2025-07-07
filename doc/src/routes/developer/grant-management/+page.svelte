<script lang="ts">
    import CodeBlock from "../../../components/CodeBlock.svelte";
    import InformationBanner from "../../../components/InformationBanner.svelte";
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('Grant Management', 'https://openid.net/specs/oauth-v2-grant-management.html'), new RowCellDefinition('Grant Management specification') ],
    ];

    let authorizationGrantHeaders: string[] = ["Name", "Description"];
    let authorizationGrantRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('grant_id'), new RowCellDefinition('Unique identifier of the grant. This is required if a grant is updated.') ],
        [ new RowCellDefinition('grant_management_action'), new RowCellDefinition('Action to perform for the grant. Either create, merge or replace. This is optional.') ]
    ];

    let queryGrantRequestHeaders: string[] = ["Name", "Description"];
    let queryGrantRequestRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('grant_id'), new RowCellDefinition('Unique identifier of the grant passed as a path parameter. This is required.') ],
    ];

    let queryGrantResponseHeaders: string[] = ["Name", "Description"];
    let queryGrantResponseRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('scopes'), new RowCellDefinition('Array of scope objects. This is required.') ],
        [ new RowCellDefinition('claims'), new RowCellDefinition('Array of claim types. This is required.') ],
        [ new RowCellDefinition('created_at'), new RowCellDefinition('Unix time in seconds of authorization grant creation. This is required.') ],
        [ new RowCellDefinition('updated_at'), new RowCellDefinition('Unix time in seconds of authorization grant latest update. This is required.') ]
    ];

    let queryGrantScopesResponseHeaders: string[] = ["Name", "Description"];
    let queryGrantScopesResponseRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('scopes'), new RowCellDefinition('Array of scopes that are allowed to be combined with the resource URI. This is required.') ],
        [ new RowCellDefinition('resources'), new RowCellDefinition('Array of resource URIs that are allowed audiences of tokens associated with the grant. It only contains one URI. This is required.') ],
    ];

    let revokeGrantRequestHeaders: string[] = ["Name", "Description"];
    let revokeGrantRequestRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('grant_id'), new RowCellDefinition('Unique identifier of the grant passed as a path parameter. This is required.') ],
    ];
</script>

<svelte:head>
	<title>Grant Management</title>
</svelte:head>

<PageTitle title="Grant Management" />
<Section title="Introduction">
    <p>
        A grant is proof of an end-user authenticating and consenting to a client to act on behalf of them.
        The grant can be single use, and when the end-user authenticates again, a new grant is created.
    </p>
    <p>
        Grants can also be re-used, by updating the grant through merging or replacing privileges of the grant.
        It is also possible to have concurrent grants.
    </p>
    <p>
        The grant can be queried and all the associated details are returned, and it is also possible to revoke a grant.
    </p>
    <br>
    <p>
        There are use cases such as incremental authorization, where privileges are added to the grant over time as needed.
        Or fine grained grants, where each grant has a small subset of privileges instead of having one large grant.
    </p>
</Section>
<Section title="Specifications">
    <Table title="Specifications" tableNumber={1} headers={specificationHeaders} rowCellDefinitions={specificationRows} />
</Section>
<Section title="Authorization grant">
    <p>
        During authorization it is possible to request a new grant to be created, or reusing an existing grant by replacing or merging privileges.
        The parameters are described in table 2.
    </p>
    <br>
    <Table title="Authorization grant request fields" tableNumber={2} headers={authorizationGrantHeaders} rowCellDefinitions={authorizationGrantRows} />
    <br>
    <InformationBanner>
        If the grant_management_action is not provided, then the default behaviour is creating a grant.
    </InformationBanner>
</Section>
<Section title="Query grant">
    <p>
        After authorization and the grant has been created, it is possible to query the grant from an endpoint.
        It can be useful to query the grant to show its content to the end-user
        or programmatically increase or decrease privileges on subsequent authorization requests.
    </p>
    <br>
    <p>
        The endpoint accepts HTTP GET and an id of the grant, which is retrieved when requesting the token endpoint.
        And an access token that requires the scope "grant_management_query" and the token must belong to the grant being queried.
    </p>
    <p>Only confidential clients are allowed to request the endpoint, as it requires client authentication.</p>
    <br>
    <p>
        The request parameters are described in table 3.
    </p>
    <br>
    <Table title="Query grant request fields" tableNumber={3} headers={queryGrantRequestHeaders} rowCellDefinitions={queryGrantRequestRows} />
    <br>
    <p>
        The response parameters are described in table 4 and 5.
    </p>
    <br>
    <Table title="Query grant response fields" tableNumber={4} headers={queryGrantResponseHeaders} rowCellDefinitions={queryGrantResponseRows} />
    <br>
    <Table title="Query grant scope response fields" tableNumber={5} headers={queryGrantScopesResponseHeaders} rowCellDefinitions={queryGrantScopesResponseRows} />
    <br>
    <p>
        The following HTTP example shows a request to the endpoint.
    </p>
    <CodeBlock>
        {`
GET /connect/grants/6faccb76-08a9-4b7e-ac7d-548c773d98ab HTTP/1.1
Host: idp.authserver.dk
Accept: application/json;charset=UTF-8
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
        `}
    </CodeBlock>
    <br>
    <p>
        The following HTTP example shows an OK response from the endpoint.
    </p>
    <CodeBlock>
        {`
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

{
  "scopes": [
    {
      "scopes": ["weather:read", "weather:write"],
      "resources": ["weather.authserver.dk"]
    },
    {
      "scopes": ["payment:read"],
      "resources": ["banking.authserver.dk"]
    }
  ],
  "claims": ["name", "given_name", "address"],
  "created_at": 1751917809,
  "updated_at": 1751917809
}
        `}
    </CodeBlock>
    <br>
    <p>
        The following HTTP example shows a NotFound response from the endpoint.
    </p>
    <CodeBlock>
        {`
HTTP/1.1 404 NotFound
Cache-Control: no-cache, no-store  
        `}
    </CodeBlock>
    <br>
    <p>
        The following HTTP example shows a Forbidden response from the endpoint.
    </p>
    <CodeBlock>
        {`
HTTP/1.1 403 Forbidden
Cache-Control: no-cache, no-store
        `}
    </CodeBlock>
</Section>
<Section title="Revoke grant">
    <p>
        After authorization and the grant has been created, it is possible to revoke the grant from an endpoint.
        It can be useful to revoke the grant when it is no longer of use. It revokes all data associated with the grant.
    </p>
    <br>
    <p>
        The endpoint accepts HTTP DELETE and an id of the grant, which is retrieved when requesting the token endpoint.
        And an access token that requires the scope "grant_management_revoke" and the token must belong to the grant being revoked.
    </p>
    <p>Only confidential clients are allowed to request the endpoint, as it requires client authentication.</p>
    <p>The response is HTTP status code 204 no content.</p>
    <br>
    <p>
        The request parameters are described in table 6.
    </p>
    <br>
    <Table title="Revoke grant request fields" tableNumber={6} headers={revokeGrantRequestHeaders} rowCellDefinitions={revokeGrantRequestRows} />
    <br>
    <p>
        The following HTTP example shows a request to the endpoint.
    </p>
    <CodeBlock>
        {`
DELETE /connect/grants/6faccb76-08a9-4b7e-ac7d-548c773d98ab HTTP/1.1
Host: idp.authserver.dk
Accept: application/json;charset=UTF-8
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
        `}
    </CodeBlock>
    <br>
    <p>
        The following HTTP example shows an OK response from the endpoint.
    </p>
    <CodeBlock>
        {`
HTTP/1.1 204 NoContent
Cache-Control: no-cache, no-store
        `}
    </CodeBlock>
    <br>
    <p>
        The following HTTP example shows a NotFound response from the endpoint.
    </p>
    <CodeBlock>
        {`
HTTP/1.1 404 NotFound
Cache-Control: no-cache, no-store  
        `}
    </CodeBlock>
    <br>
    <p>
        The following HTTP example shows a Forbidden response from the endpoint.
    </p>
    <CodeBlock>
        {`
HTTP/1.1 403 Forbidden
Cache-Control: no-cache, no-store
        `}
    </CodeBlock>
</Section>