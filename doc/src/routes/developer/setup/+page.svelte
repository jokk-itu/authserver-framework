<script>
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
</script>

<PageTitle title="Setup" />
<Section title="Introduction">
    <p>The following sections describe how to setup AuthServer framework
        in your solution.
    </p>
</Section>
<Section title="Options">
    <p>
        JwksDocument options UserInteraction options DiscoveryDocument options
    </p>
</Section>
<Section title="Feature management">
    <p>
        Features, examples on enable/disable
    </p>
</Section>
<Section title="Interfaces">
    <p>
        Implement interface IDistibutedCache Implement interface
        IUserClaimService Implement interface IAuthenticatedUserAccessor
        Implement interface IAuthenticationContextReferenceResolver
    </p>
</Section>
<Section title="Startup">
    <p>
        AddAuthServer during setup of services UseAuthServer during setup of
        request pipeline
    </p>
</Section>
<Section title="Migrations">
    <p>
        Explain that EntityFramework Core can be used to migrate the database
    </p>
</Section>
<Section title="Database">
<p>
    Explain the needed data that must be setup in the database
</p>
</Section>