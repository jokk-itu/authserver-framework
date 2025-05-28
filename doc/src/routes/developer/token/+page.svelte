<script lang="ts">
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";

    let grantTypeHeaders: string[] = ["Name", "Description"];
    let grantTypeRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('Authorization Code'), new RowCellDefinition('Use a code in exchange of tokens.') ],
        [ new RowCellDefinition('Refresh Token'), new RowCellDefinition('Use a refresh token in exchange of tokens.') ],
        [ new RowCellDefinition('Client Credentials'), new RowCellDefinition('Use client authentication in exchange of tokens.') ]
    ];

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('OAuth2.1', 'https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/'), new RowCellDefinition('Core specification for OAuth') ],
        [ new RowCellDefinition('OpenId Connect', 'https://openid.net/specs/openid-connect-core-1_0.html'), new RowCellDefinition('Core specification for OpenId Connect') ],
        [ new RowCellDefinition('JWT', ''), new RowCellDefinition('') ],
        [ new RowCellDefinition('JWS', ''), new RowCellDefinition('') ],
        [ new RowCellDefinition('JWE', ''), new RowCellDefinition('') ],
        [ new RowCellDefinition('Resource', ''), new RowCellDefinition('') ],
        [ new RowCellDefinition('Step up authentication', ''), new RowCellDefinition('') ]
    ];
</script>

<svelte:head>
	<title>Token Endpoint</title>
</svelte:head>

<PageTitle title="Token" />
<Section title="Introduction">
    <p>
        The token endpoint, in general terms, is used to get access tokens through grants.
        The grants are identified through a grant type. The supported grant types are listed in Table 1.
    </p>
    <br> 
    <Table title="Grant types" tableNumber={1} headers={grantTypeHeaders} rowCellDefinitions={grantTypeRows} />
</Section>
<Section title="Specifications">
    <Table title="Specifications" tableNumber={2} headers={specificationHeaders} rowCellDefinitions={specificationRows} />
</Section>
<Section title="Token structure">
    <p>The tokens returned can be in different formats. The supported formats are JWT or Reference.</p>
    <br>
    <p>JWT is a well structured token format using JSON, and it supports signatures and encryption.</p>
    <br>
    <p>Reference is a random string, which is only understood by AuthServer. The content of the token, can be retrieved from the Introspection endpoint.</p>
    <br>
    <p>The client can choose between the two in its metadata, through the field "UseReferenceToken".</p>
    <p>If bandwidth of the client is of concern, or you require the content of token is only send through backchannels, then the Reference token is a suitable candidate.
        It however requires an extra roundtrip at the protected resource, to verify the token at AuthServer.
    </p>
    <br>
    <p>Finally, it is also possible to sender-constraint a token, irrespective of its structure.</p>
    <p>It means the token is cryptographically bound to the client that requested the token, and therefore can only be used by that client.</p>
    <p>This is achievable through DPoP.</p>
</Section>
<Section title="Fine grained tokens">
    <p>It is recommended that tokens have a short lifespan, in minutes and at most an hour.</p>
    <p>This can be adjusted for each client in its metadata. Each type of token, has a specific field for adjusting its expiration.</p>
    <br>
    <p>It is recommended that tokens are only used at protected resources, which the client requests.</p>
    <p>This is done through the "resource" parameter, which is a single protected resource absolute base URI.
        The parameter can be provided as many times as needed, and the URI is visible in the audience claim.
    </p>
    <p>For example if a protected resource URI is reachable at "https://weather.authserver.dk", then that URI will be provded as the resource parameter.</p>
    <br>
    <p>It is recommended that tokens are only used for what they request.</p>
    <p>This is done through the "scope" parameter, which is a space seperated string of scopes that the token is authorized for.</p>
    <p>For example if a token must be used to fetch data about the weather, and the scope required for requesting weather is named "weather:read".
        Then the scope parameter will be set to "weather:read".
    </p>
</Section>
<Section title="Access token claims">
    <p>TODO write about the claims and list in a table</p>
</Section>
<Section title="Id token claims">
    <p>TODO write about the claims and list in a table</p>
</Section>
<Section title="Token Endpoint">
    <p>Write about the request parameters</p>
    <p>Write about the response parameters</p>
</Section>