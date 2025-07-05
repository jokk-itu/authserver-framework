<script lang="ts">
    import CodeBlock from "../../../components/CodeBlock.svelte";
    import InformationBanner from "../../../components/InformationBanner.svelte";
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import Table from "../../../components/Table.svelte";
    import { RowCellDefinition } from "../../../table";

    let specificationHeaders: string[] = ["Name", "Description"];
    let specificationRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('Grant Management', 'https://openid.net/specs/fapi-grant-management-01.html'), new RowCellDefinition('Grant Management specification') ],
    ];

    let grantHeaders: string[] = ["Name", "Description"];
    let grantRows: RowCellDefinition[][] = [
        [ new RowCellDefinition('grant_id'), new RowCellDefinition('Unique identifier of the grant. This is required if a grant is updated.') ],
        [ new RowCellDefinition('grant_management_action'), new RowCellDefinition('Action to perform for the grant. Either create, merge or replace. This is optional.') ]
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
<Section title="Grant">
    <p>
        During authorization it is possible to request a new grant to be created, or reusing an existing grant by replacing or merging privileges.
        The parameters are described in table 2.
    </p>
    <br>
    <Table title="Grant request fields" tableNumber={2} headers={grantHeaders} rowCellDefinitions={grantRows} />
    <br>
    <InformationBanner>
        If the grant_management_action is not provided, then the default behaviour is creating a grant.
    </InformationBanner>
</Section>
<Section title="Query grant">
    <p>Querying grants</p>
</Section>
<Section title="Revoke grant">
    <p>Revoking grants</p>
</Section>