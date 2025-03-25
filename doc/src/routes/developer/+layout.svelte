<script lang="ts">
    import { base } from '$app/paths';
  </script>

<div class="flex">
    <nav class="mx-4 w-48 rounded-md outline-8 bg-zinc-200">
        <ul class="mx-2 my-2 space-y-4">
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
                <a href="{base}/developer/client-authentication">Client Authentication</a>
            </li>
        </ul>
    </nav>
    <div class="flex-auto"><slot /></div>
</div>

<style>
</style>
