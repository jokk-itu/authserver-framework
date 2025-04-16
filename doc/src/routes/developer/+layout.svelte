<script lang="ts">
    import { base } from "$app/paths";
    import { developerLinks } from '../../links';
</script>

<div class="flex">
    <!-- leftside nav, only shown on larger screens -->
    <nav class="hidden lg:block sm:flex-none mx-4 w-56 rounded-md outline-8">
        <ul class="rounded-md [&>li]:px-4 py-4 space-y-4 text-lg bg-zinc-200">
            {#each developerLinks as developerLink}
                <li class="hover:underline">
                    <a href="{developerLink.Href}">{developerLink.Name}</a>
                </li>
            {/each}
        </ul>
    </nav>

    <!-- documentation page -->
    <div class="flex-auto w-full"><slot /></div>
</div>