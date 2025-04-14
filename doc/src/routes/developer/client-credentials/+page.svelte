<script lang="ts">
    import CodeBlock from "../../../components/CodeBlock.svelte";
    import InformationBanner from "../../../components/InformationBanner.svelte";
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition("OAuth2.1", "https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/"), new RowCellDefinition("Core specification for OAuth") ],
        [ new RowCellDefinition("OpenId Connect", "https://openid.net/specs/openid-connect-core-1_0.html"), new RowCellDefinition("Core specification for OpenId Connect") ],
        [ new RowCellDefinition("JWT Assertion framework", "https://datatracker.ietf.org/doc/rfc7523/"), new RowCellDefinition("Core specification for OAuth") ],
        [ new RowCellDefinition("Assertion framework", "https://datatracker.ietf.org/doc/rfc7521/"), new RowCellDefinition("Specification for OAuth assertions") ],
    ];
</script>

<PageTitle title="Client Credentials" />
<Section title="Introduction">
    <p>TODO</p>
</Section>
<Section title="Specifications">
    <Table title="Specifications" tableNumber={1} headers={specificationHeaders} rowCellDefinitions={specificationRows} />
</Section>