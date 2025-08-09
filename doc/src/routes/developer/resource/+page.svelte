<script lang="ts">
    import CodeBlock from "../../../components/CodeBlock.svelte";
import InformationBanner from "../../../components/InformationBanner.svelte";
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('Resource Indicators', 'https://datatracker.ietf.org/doc/html/rfc8707'), new RowCellDefinition('Specification for specifying resources') ],
        [ new RowCellDefinition('Protected Resource Metadata', 'https://datatracker.ietf.org/doc/html/rfc9728/'), new RowCellDefinition('Specification for protected resource metadata') ]
    ];
</script>

<svelte:head>
	<title>Resource Indicators</title>
</svelte:head>

<PageTitle title="Resource Indicators" />
<Section title="Introduction">
    <p>
        Access tokens are usable at resources, where their identifier is in the audience claim of the access token.
        The audience claim is deduced by the client passing resource indicators as the request parameter "resource".
    </p>
    <br>
    <InformationBanner>
        The resource indicator is required, to demand the client specifies which resources are the intended audience.
        If that is not a requirement, then all resources authorized for the requested scope, would have to be specified as the audience in the token,
        whether or not the resources are intended for usage.
        This means the resource indicators are used to enforce least privilege for tokens.
    </InformationBanner>
</Section>
<Section title="Specifications">
    <Table title="Specifications" tableNumber={1} headers={specificationHeaders} rowCellDefinitions={specificationRows} />
</Section>
<Section title="Indicating resources">
    <p>
        The resource parameter must be one or many URIs, which match the ClientUri of a registered Client at the AuthServer.
        The available resources are specified at the discovery endpoint, identified by the field 'protected_resources'.
    </p>
    <p>
        The resource can only be specified as an audience, if it is authorized for at least one of the requested scopes.
    </p>
    <br>
    <p>The following HTTP example is a token request, with multiple resource parameters.</p>
    <p>The resource parameters are then used as the audience in the issued access token.</p>
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
    <p>The following HTTP example is an incomplete authorize request, with multiple resource parameters.</p>
    <p>The resource parameters are then used as the authorized audience of issued access tokens, in relation to the grant of the authorize request.</p>
    <p>The resources are authorized once the end user has consented to the authorization request.</p>
    <CodeBlock>
{`
GET /connect/authorize?resource=https%3A%2F%2Fapi-one.protectedresource.dk&resource=https%3A%2F%2Fapi-two.protectedresource.dk HTTP/1.1
Host: idp.authserver.dk
`}
    </CodeBlock>
</Section>