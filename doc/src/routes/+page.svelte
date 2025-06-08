<script lang="ts">
    import Terminal from "../components/Terminal.svelte";
</script>

<svelte:head>
	<title>AuthServer Home Page</title>
</svelte:head>

<div class="flex flex-col sm:flex-row sm:justify-evenly">
    <div>
        <h1 class="text-4xl mb-2">Authorization made easy</h1>
        <h2 class="text-xl mb-4">
            AuthServer is built for easy setup with strict security requirements
        </h2>
        <ul class="pl-5 list-disc">
            <li class="py-2">OAuth 2.1 ready</li>
            <li class="py-2">Secure by default</li>
            <li class="py-2">Easily setup an IdentityProvider</li>
            <li class="py-2">Fast, reliable and scalable</li>
            <li class="py-2">Monitor capability using Open Telemetry</li>
        </ul>
        <br>
        <div class="my-12">
            <a href="https://github.com/jokk-itu/authserver-framework" class="rounded bg-openid px-8 py-3">Learn more</a>
        </div>
    </div>
    <div>
        <Terminal />
    </div>
</div>