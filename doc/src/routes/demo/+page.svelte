<svelte:head>
	<title>Demo Documentation</title>
</svelte:head>

<h1 class="text-4xl mb-2">Demo</h1>
<p class="mb-4">
    Illustrating the capabilities of AuthServer is best done through examples.
    <br><br>
    AuthServer has therefore been implemented and deployed for everyone to use.
    Different clients and protected resources are also deployed,
    which interact with AuthServer, and illustrate the features possible with AuthServer.
</p>


<h2 class="text-xl mb-4">Applications</h2>

<div class="grid gap-4 grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
    <!-- IdentityProvider -->
    <div class="max-w rounded overflow-hidden shadow-lg px-6 py-4">
        <div class="font-bold text-xl mb-2">IdentityProvider</div>
        <p class="text-gray-800 text-base">
            WebApp using the AuthServer framework, to behave as an IdentityProvider.
            <br>
            It uses AspNetCore.Identity for user management.
        </p>
    </div>

    <!-- WebClient -->
    <div class="max-w rounded overflow-hidden shadow-lg px-6 py-4">
        <div class="font-bold text-xl mb-2">WebClient</div>
        <p class="text-gray-800 text-base">
            WebApp using FAPI features to enable high security.
        </p>
    </div>

    <!-- BFF Client -->
    <div class="max-w rounded overflow-hidden shadow-lg px-6 py-4">
        <div class="font-bold text-xl mb-2">BFF Client</div>
        <p class="text-gray-800 text-base">
            Blazor WebAssembly app, using the BackEnd for FrontEnd pattern,
            to enable high security for a browser based app. 
        </p>
    </div>

    <!-- Worker Client -->
    <div class="max-w rounded overflow-hidden shadow-lg px-6 py-4">
        <div class="font-bold text-xl mb-2">Worker Client</div>
        <p class="text-gray-800 text-base">
            Worker app without user interface, and only uses the client_credentials grant.
        </p>
    </div>

    <!-- Browser Client -->
    <div class="max-w rounded overflow-hidden shadow-lg px-6 py-4">
        <div class="font-bold text-xl mb-2">Browser Client</div>
        <p class="text-gray-800 text-base">
            Browser app behaving as a SPA without a backend responsible for authentication.
        </p>
        <p class="text-openid font-bold">Work in progress</p>
    </div>

    <!-- Desktop Client -->
    <div class="max-w rounded overflow-hidden shadow-lg px-6 py-4">
        <div class="font-bold text-xl mb-2">Desktop Client</div>
        <p class="text-gray-800 text-base">
            Desktop app behaving as a native app without a backend responsible for authentication.
        </p>
        <p class="text-openid font-bold">Work in progress</p>
    </div>

    <!-- Weather Client -->
    <div class="max-w rounded overflow-hidden shadow-lg px-6 py-4">
        <div class="font-bold text-xl mb-2">Weather Client</div>
        <p class="text-gray-800 text-base">
            Simple API behaving as a protected resource. It handles public information and requires little authorization.
        </p>
    </div>

    <!-- Banking Client -->
    <div class="max-w rounded overflow-hidden shadow-lg px-6 py-4">
        <div class="font-bold text-xl mb-2">Banking Client</div>
        <p class="text-gray-800 text-base">
            Strict API behaving as a protected resource. It handles highly sensitive information and requires strict authorization.
        </p>
    </div>
</div>