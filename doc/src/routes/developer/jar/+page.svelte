<script lang="ts">
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition("JWT-Secured Authorization Request", "https://datatracker.ietf.org/doc/html/rfc9101"), new RowCellDefinition("Specification to secure authorization requests using JWT") ]
    ];
</script>

<svelte:head>
	<title>JWT-Secured Authorization Request</title>
</svelte:head>

<PageTitle title="JWT-Secured Authorization Request" />
<Section title="Introduction">
    <p>
        Introduction to JWT secured authorization
    </p>
</Section>
<Section title="Specifications">
    <Table title="Specifications" tableNumber={1} headers={specificationHeaders} rowCellDefinitions={specificationRows} />
</Section>
<Section title="Authorization">
    <p>
        Introduce to the usage of authorize, pushed authorization, device authorization.
    </p>
</Section>