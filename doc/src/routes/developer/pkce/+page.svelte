<script lang="ts">
    import CodeBlock from "../../../components/CodeBlock.svelte";
    import InformationBanner from "../../../components/InformationBanner.svelte";
import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('OAuth2.1', 'https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/'), new RowCellDefinition('Core specification for OAuth') ],
        [ new RowCellDefinition('OAuth Discovery Metadata', 'https://datatracker.ietf.org/doc/html/rfc8414'), new RowCellDefinition('Core specification for OAuth discovery metadata') ]
    ];
</script>

<svelte:head>
	<title>Proof Key for Code Exchange</title>
</svelte:head>

<PageTitle title="Proof Key for Code Exchange" />
<Section title="Introduction">
    <p>
        PKCE which is short for Proof Key for Code Exchange, is used to mitigate the risks of code exchanges, such as authorization codes and device codes.
        It works by the client creating a secret, which is hashed, and send along the initial authentication request.
        Then the secret is sent along the token request,
        and the authorization server verifies the secret hashed is equal to the hash from the initial authentication request.
    </p>
    <br>
    <p>
        The proof key protects the client against malicious actors, who successfully intercepts codes and redeems them for a token.
        This is because the malicous actor is not in possession of the code_verifier, and the token request will therefore fail.
    </p>
</Section>
<Section title="Specifications">
    <Table title="Specifications" tableNumber={1} headers={specificationHeaders} rowCellDefinitions={specificationRows} />
</Section>
<Section title="Proof Key">
    <p>The flow starts by the client generating a secret using a cryptographically strong random generator.</p>
    <p>The secret must be unique for each authentication request, and not reused.</p>
    <p>Then the secret is hashed using one of the supported code_challenge_methods, e.g. S256 which uses SHA256.</p>
    <InformationBanner>
        <p>The code_challenge_method "plain" is not supported, as that would expose the code_verifier value and make the Proof Key useless.</p>
    </InformationBanner>
    <br>
    <p>The following example shows an initial authentication request.</p>
    <CodeBlock>
        {`
POST /connect/authorize HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded

code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
&code_challenge_method=S256
        `}
    </CodeBlock>
    <p>The following example shows the token request.</p>
    <CodeBlock>
        {`
POST /connect/token HTTP/1.1
Host: idp.authserver.dk
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=authorization_code
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
        `}
    </CodeBlock>
</Section>