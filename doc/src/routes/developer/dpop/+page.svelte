<script lang="ts">
    import CodeBlock from "../../../components/CodeBlock.svelte";
    import InformationBanner from "../../../components/InformationBanner.svelte";
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition("DPoP", "https://datatracker.ietf.org/doc/html/rfc9449"), new RowCellDefinition("Specification for sender constraining tokens using DPoP") ],
    ];

    let dPoPTokenHeaders: string[] = ["Name", "Description"];
    let dPoPTokenFields: RowCellDefinition[][] = [
        [ new RowCellDefinition("htm"), new RowCellDefinition("HTTP method used at the request. This is a required claim.") ],
        [ new RowCellDefinition("htu"), new RowCellDefinition("HTTP absolute URL used at the request. This is a required claim.") ],
        [ new RowCellDefinition("nonce"), new RowCellDefinition("Server provided nonce. This is a required claim.") ],
        [ new RowCellDefinition("ath"), new RowCellDefinition("Hash of the access token that is bound to the DPoP token. This is a required claim when requests use the bound access token.") ],
        [ new RowCellDefinition("jwk"), new RowCellDefinition("Public JsonWebKey used to verify the signature of the DPoP token. This is a required header.") ],
        [ new RowCellDefinition("typ"), new RowCellDefinition("Type of JsonWebToken. This is a required header and must be dpop+jwt.") ],
        [ new RowCellDefinition("jti"), new RowCellDefinition("Unique identifier of the DPoP token. This is a required claim.") ],
        [ new RowCellDefinition("exp"), new RowCellDefinition("Unix timestamp when the DPoP token expires. This is a required claim.") ],
        [ new RowCellDefinition("iat"), new RowCellDefinition("Unix timestamp when the DPoP token was issued. This is a required claim.") ],
        [ new RowCellDefinition("nbf"), new RowCellDefinition("Unix timestamp when the DPoP token is active from. This is a required claim.") ],
    ];
</script>

<svelte:head>
	<title>DPoP</title>
</svelte:head>

<PageTitle title="DPoP" />
<Section title="Introduction">
    <p>
        Demonstrating Proof of Possession (DPoP) is a method to sender constraint tokens.
        It means the client that received the token from AuthServer at the token endpoint,
        is the only one that can send the token to protected resources.
    </p>
</Section>
<Section title="Specifications">
    <Table title="Specifications" tableNumber={1} headers={specificationHeaders} rowCellDefinitions={specificationRows} />
</Section>
<Section title="DPoP flow">
    <p>
        Public and Confidential clients can use DPoP and is an optional addition to increase security and reduce misuse of tokens.
    </p>
    <br>
    <InformationBanner>
        It is possible for public clients to use DPoP
        because the private key used for signing DPoP tokens is not associated with the client metadata used by AuthServer.
    </InformationBanner>
    <br>
    <p>
        If a client uses DPoP then it is required in the entire flow when retrieving an access token.
        For the "authorization_code" grant type it means DPoP must be used during authorize and at the token endpoint.
        When requesting protected resources using a DPoP bound access token, it is always required to present a DPoP proof.
    </p>
    <br>
    <p>Access tokens and Refresh tokens can be DPoP bound.</p>
    <InformationBanner>
        Only public clients will have their refresh tokens bound,
        because confidential clients have their refresh token bound using client authentication.
    </InformationBanner>
    <br>
    <p>
        Even though DPoP is optional at AuthServer, then a client can require DPoP usage through its client metadata.
        Then if an endpoint that can accept DPoP usage, does not receive DPoP parameters in requests associated with the client,
        the request will fail.
    </p>
</Section>
<Section title="DPoP token">
    <p>
        The DPoP token is a structured JWT and is signed using one of the algorithms from the discovery endpoint.
        The token can contain the fields in table 2.
    </p>
    <br>
    <Table title="DPoP token fields" tableNumber={2} headers={dPoPTokenHeaders} rowCellDefinitions={dPoPTokenFields} />
    <br>
    <p>The following JSON example shows a base64 decoded DPoP token sent to the token endpoint.</p>
    <br>
    <CodeBlock>
        {`
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk":
  {
    "kty": "EC",
    "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
    "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
    "crv": "P-256"
  }
}
.
{
  "jti": "b1a4262d-89fb-4d5a-b662-f1b637241a88",
  "htm": "POST",
  "htu": "https://idp.authserver.dk/connect/token",
  "nonce": "eyJ7S_zG.eyJH0-Z.HX4w-7v",
  "iat": 1562262616,
  "nbf": 1562262616,
  "exp": 1562262676
}
        `}
    </CodeBlock>
    <br>
    <p>The following JSON example shows a base64 decoded DPoP token sent to a protected resource.</p>
    <CodeBlock>
        {`
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk":
  {
    "kty": "EC",
    "x": "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
    "y": "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA",
    "crv": "P-256"
  }
}
.
{
  "jti": "b1a4262d-89fb-4d5a-b662-f1b637241a88",
  "htm": "GET",
  "htu": "https://api.authserver.dk/data",
  "nonce": "eyJ7S_zG.eyJH0-Z.HX4w-7v",
  "ath":"fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo",
  "iat": 1562262616,
  "nbf": 1562262616,
  "exp": 1562262676
}
        `}
    </CodeBlock>
</Section>
<Section title="DPoP nonce">
    <p>
        The DPoP nonce is generated by the server and is used to make sure DPoP tokens cannot be made for the future,
        if the private key is leaked.
    </p>
    <p>The DPoP nonce is provided through error responses, when a DPoP token contains a missing nonce or a stale nonce.</p>
    <p>The lifetime of DPoP nonces are controlled by the client through its metadata.</p>
    <p>An example of a response containing a DPoP nonce can be seen below.</p>
    <CodeBlock>
        {`
HTTP/1.1 400 Bad Request
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store
DPoP-Nonce: eyJ7S_zG.eyJH0-Z.HX4w-7v

{
  "error": "use_dpop_nonce",
  "error_description": "nonce is required for dpop"
}
        `}
    </CodeBlock>
</Section>