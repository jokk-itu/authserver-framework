<script lang="ts">
    import Highlight from "svelte-highlight";
    import csharp from "svelte-highlight/languages/csharp";

    export let code: string
</script>

<Highlight language={csharp} code={code} />