<script>
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";

    import { base } from '$app/paths';
</script>

<PageTitle title="Architecture" />
<p>Write introduction to the architecture page</p>
<Section title="Endpoints">
    <p>explain all endpoints adhere to the same pattern</p>
    <img src="{base}/endpoint-architecture.png" alt="endpoint architecture"/>
    <p>explain the responsibilities of the different interfaces</p>
</Section>
<Section title="Modules">
    <p>
        explain that functionality is wrapped in modules, and can be
        enabled/disabled
    </p>
</Section>
<Section title="Cache">
    <p>explain that clients are cached</p>
</Section>
