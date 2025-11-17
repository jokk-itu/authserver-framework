<script lang="ts">
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('Device Authorization', 'https://datatracker.ietf.org/doc/html/rfc8628'), new RowCellDefinition('Specification for device authorization') ]
    ];
</script>

<svelte:head>
	<title>Device Authorization</title>
</svelte:head>

<PageTitle title="Device Authorization" />
<Section title="Introduction">
    <p>
        Introduce to Device Authorization
    </p>
</Section>
<Section title="Specifications">
    <Table title="Specifications" tableNumber={1} headers={specificationHeaders} rowCellDefinitions={specificationRows} />
</Section>
<Section title="Device Authorization Endpoint">
    <p>Describe the flow of authorization</p>
    <p>Describe the request parameters</p>
    <p>Describe the response parameters</p>
    <p>Show an example of a request</p>
    <p>Show an example of a successful response</p>
    <p>Show an example of a failure response</p>
</Section>
<Section title="Redeeming the user code">
    <p>Describe redeeming the code</p>
</Section>
<Section title="Device Code Grant">
    <p>Describe the flow of the token endpoint</p>
    <p>Show example of a request</p>
    <p>Show an example of a polling response</p>
    <p>Show an example of a successful response</p>
</Section>