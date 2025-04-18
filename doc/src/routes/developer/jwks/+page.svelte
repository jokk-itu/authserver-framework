<script lang="ts">
    import CodeBlock from "../../../components/CodeBlock.svelte";
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('JSON Web Key', 'https://datatracker.ietf.org/doc/html/rfc7517'), new RowCellDefinition('Core specification for JSON Web Key') ]
    ];

    let jwksHeaders: string[] = ["Name", "Description"];
    let jwksRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('keys'), new RowCellDefinition('Array of Json Web Keys') ],
        [ new RowCellDefinition('kty'), new RowCellDefinition('The cryptographic algorithm family, the key can use') ],
        [ new RowCellDefinition('use'), new RowCellDefinition('The usage of the key') ],
        [ new RowCellDefinition('alg'), new RowCellDefinition('The cryptographic algorithm the key can be used with') ],
        [ new RowCellDefinition('key_ops'), new RowCellDefinition('The operations the key can be used with') ],
        [ new RowCellDefinition('kid'), new RowCellDefinition('The unique identifier of the key') ],

        [ new RowCellDefinition('crv'), new RowCellDefinition('The elliptic curve used by the key') ],
        [ new RowCellDefinition('x'), new RowCellDefinition('The base64 x coordinate on the curve') ],
        [ new RowCellDefinition('y'), new RowCellDefinition('The base64 y coordinate on the curve') ],

        [ new RowCellDefinition('n'), new RowCellDefinition('The modulus value used with kty: RSA') ],
        [ new RowCellDefinition('e'), new RowCellDefinition('The exponnent value used with kty: RSA') ],

        [ new RowCellDefinition('x5t'), new RowCellDefinition('The SHA1 thumpbrint of the certificate') ],
        [ new RowCellDefinition('x5c'), new RowCellDefinition('Array of one base64 certificate') ],
        [ new RowCellDefinition('x5t#S256'), new RowCellDefinition('The SHA256 thumbprint of the certificate') ],
    ];
</script>

<svelte:head>
	<title>JWKS endpoint page of AuthServer</title>
</svelte:head>

<PageTitle title="Discovery" />
<Section title="Introduction">
    <p>The JWKS endpoint returns a JSON document containing public keys used for verifying signatures in tokens, and encrypting tokens.</p>
</Section>
<Section title="Specifications">
    <Table title="Specifications" tableNumber={1} headers={specificationHeaders} rowCellDefinitions={specificationRows} />
</Section>
<Section title="JWKS Endpoint">
    <p>The jwks endpoint is invoked through HTTP using the GET method.</p>
    <p>The following exmaple is a GET request to the jwks endpoint.</p>
    <CodeBlock>
        {`
GET /.well-known/jwks HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/json

{
  "keys": [
    {
      "kty": "EC",
      "use": "enc",
      "crv": "P-256",
      "alg": "ECDH-ES+A128KW",
      "key_ops": ["encryption"],
      "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "kid": "d890e7ed-662b-48c5-8914-c5c58571f8b6"
    }
  ]
}
        `}
    </CodeBlock>
    <p>The following table describes the fields in the JSON document.</p>
    <Table title="JWKS fields" tableNumber={3} headers={jwksHeaders} rowCellDefinitions={jwksRows} />
</Section>