<script lang="ts">
    import { base } from "$app/paths";
</script>

<div class="flex">
    <!-- leftside nav, only shown on larger screens -->
    <nav class="hidden lg:block sm:flex-none mx-4 w-56 rounded-md outline-8">
        <ul class="rounded-md [&>li]:px-4 py-4 space-y-4 text-lg bg-zinc-200">
            <li class="hover:underline">
                <a href="{base}/developer/architecture">Architecture</a>
            </li>
            <li class="hover:underline">
                <a href="{base}/developer/datamodel">Datamodel</a>
            </li>
            <li class="hover:underline">
                <a href="{base}/developer/setup">Setup</a>
            </li>
            <li class="hover:underline">
                <a href="{base}/developer/client-authentication"
                    >Client Authentication</a
                >
            </li>
        </ul>
    </nav>

    <!-- documentation page -->
    <div class="flex-auto w-full"><slot /></div>
</div>