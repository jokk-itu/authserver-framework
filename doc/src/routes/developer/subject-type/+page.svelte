<script lang="ts">
    import CodeBlock from "../../../components/CodeBlock.svelte";
    import InformationBanner from "../../../components/InformationBanner.svelte";
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('OpenId Connect', 'https://openid.net/specs/openid-connect-core-1_0.html'), new RowCellDefinition('Core specification for OpenId Connect') ],
    ];
</script>

<svelte:head>
	<title>Subjct Type</title>
</svelte:head>

<PageTitle title="Subject Type" />
<Section title="Introduction">
    <p>
        The subject is a unique identifier for an entity, which is either the end-user or the client.
        It is used as the sub claim in access tokens and id tokens.
    </p>
    <br>
    <p>
        The value can be globally used from AuthServer among all clients,
        or the value can be scoped to a sector identifier, where clients using the same sector identifier will share the same subjects.
    </p>
    <br>
    <p>
        Determining the type of the subject is done through the client metadata "subject_type".
        The available subject types are found at the discovery endpoint. There are two available values "public" and "pairwise".
    </p>
</Section>
<Section title="Specifications">
    <Table title="Specifications" tableNumber={1} headers={specificationHeaders} rowCellDefinitions={specificationRows} />
</Section>
<Section title="Public">
    <p>
        Subjects that are public are shared among all clients from AuthServer.
        The unique identifier of the end-user is used as the subject value.
    </p>
    <p>
        The public subject type might be unacceptable for high security scenarios, where anonymity is required.
        Because the public subject can be used to track end-user activity across all clients in the end-users single-sign-on session.
    </p>
</Section>
<Section title="Pairwise">
    <p>
        Subjects that are pairwise are shared among all clients that use the same sector identifier.
        For each unique sector identifier, there will be a unique subject for each end-user.
        Resulting in an end-user having many subjects.
    </p>
    <p>
        It can be useful to share the same sector identifier among multiple clients, if the clients have a trust among them.
        For example an enterprise having multiple programs they own, where they want to track an end-users activity between all their owned clients.
    </p>
    <br>
    <p>
        The sector identifier is provided as client metadata and done through "sector_identifier_uri".
        It must be an HTTPS absolute URI which responds with a JSON array of all the client uris that share the sector_identifier_uri.
        That makes sure a malicious client cannot register a sector_identifier_uri that is only supposed to shared among trusted clients.
    </p>
    <InformationBanner>
        The sector_identifier_uri should not be considered a secret, as it cannot be used to register malicious clients,
        or deduce the pairwise subjects of end-users.
    </InformationBanner>
    <br>
    <InformationBanner>
        The URIs in the response must match the values from the client's registered "client_uri" at AuthServer.
    </InformationBanner>
    <br>
    <p>The following HTTP example shows a request from AuthServer to the sector_identifer_uri.</p>
    <CodeBlock>
        {`
GET /sector-identifier HTTP/1.1
Host: client.authserver.dk
Accept: application/json
        `}
    </CodeBlock>
    <p>The following HTTP example shows a response where the sector_identifier_uri responds with trusted client uris.</p>
    <CodeBlock>
        {`
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-cache, no-store

["https://client.authserver.dk"]
        `}
    </CodeBlock>
</Section>