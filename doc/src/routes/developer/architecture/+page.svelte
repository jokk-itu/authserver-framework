<script>
    import PageTitle from "../../../components/PageTitle.svelte";
    import Section from "../../../components/Section.svelte";
    import { base } from "$app/paths";
</script>

<PageTitle title="Architecture" />
<Section title="Introduction">
    <p>
        The AuthServer framework has been built as a single NuGet package.
    </p>
</Section>
<Section title="Endpoints">
    <p>
        Endpoints have been designed as a minimum HTTP handler, with an accessor
        to parse the request, and a handler to validate and process the request.
        <br />
    </p>
    <br/>
    <figure>
        <img class="object-center" src="{base}/endpoint-architecture.png" alt="endpoint architecture" />
        <figCaption class="text-center">Image 1: Class diagram of request handling</figCaption>
    </figure>
    <br/>
    <p>
        <b>IRequestAccessor</b> is responsible for parsing the request into a
        single request. It can for example contain parsed headers, query
        parameters and body parameters.
        <br /><br />
        <b>RequestHandler</b> is responsible for accepting a request, then
        validate it through its <b>IRequestValidator</b> and if valid, then
        process it through <b>IRequestProcessor</b>.
        <br /><br />
        <b>IEndpointHandler</b> is the HTTP request entrypoint and is
        responsible for handling the request by using <b>IRequestHandler</b> and
        <b>IRequestAccessor</b>.
    </p>
</Section>
<Section title="Modules">
    <p>
        The AuthServer framework consists of a single csharp project, containing
        feature folders, and core functionality shared across features.
        <br /><br />
        For example, the authorize endpoint is a single feature, but some functionality
        is shared with the pushed authorization feature.
        <br /><br />
        Consumers of the framework might not use all features that AuthServer has
        to offer, and therefore each feature can be enabled or disabled.
        <br />
        Some features, like Dynamic Client Registration offers fine grained feature
        control, grouped by action.
        <br />
        Therefore, getting a client is one feature, whereas creating a client is
        another feature.
        <br /><br />
        Managing features is implemented through the Microsoft.FeatureManagement
        library.
    </p>
    <br/>
    <figure>
        <img class="mx-auto" src="{base}/module-architecture.png" alt="module architecture"/>
        <figcaption class="text-center">Image 2: State machine diagram of module handling</figcaption>
    </figure>
    <br/>
    <p>
        The feature flag filter is responsible for checking all incoming HTTP requests,
        whether the endpoint it reaches has been enabled through FeatureManagement.
        If it has been enabled, the execution flow continues normally,
        if it has not, then the request is cancelled immediately and the HTTP status code 404 is returned.
        <br/>
        The feature flag check is also handled in the Discovery endpoint,
        to make sure metadata about disabled features is not exposed.
    </p>
</Section>
<Section title="Cache">
    <p>
        The <b>Client</b> and related data is accessed in almost every request,
        and that is by far mostly reading the client, as updating the client should rarely be done.
        Therefore, to alleviate the data store, all clients are cached in a distributed cache,
        for faster retrieval of data.
    </p>
</Section>