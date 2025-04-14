<script lang="ts">
    export let title: String;
</script>

<div class="mb-8" id={title.toLowerCase()}>
    <div class="inline-flex">
        <a class="hover:underline ref-link text-xl" href="#{title.toLowerCase()}">{title}</a>
    </div>
    <hr class="mb-4" />
    <slot />
</div>