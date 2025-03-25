<script lang="ts">
    import Highlight from "svelte-highlight";
    import http from "svelte-highlight/languages/http";

    export let code: string
</script>

<Highlight language={http} code={code} />