<script lang="ts">
  import { base } from "$app/paths";
  import NavbarLogo from "./NavbarLogo.svelte";

  let isMobileMenuOpen = false;

  function openMobileMenu() {
    isMobileMenuOpen = true;
  }

  function closeMobileMenu() {
    isMobileMenuOpen = false;
  }
</script>

<nav
  class:hidden={!isMobileMenuOpen}
  class="backdrop-saturate-200 backdrop-blur-md z-50 flex fixed top-0 bottom-0 left-0 right-0 overflow-y-auto"
>
  <div class="w-full min-h-full max-w-80 bg-zinc-200">
    <div class="px-4 pt-6">
      <button onclick={closeMobileMenu} aria-label="Close mobile menu">
        <svg class="w-4 h-4" viewBox="0 0 24 24">
          <path
            fill="none"
            stroke="currentColor"
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M6 18L18 6M6 6l12 12"
          /></svg
        >
      </button>
    </div>
    <div>
      <ul class="rounded-md [&>li]:px-4 py-4 space-y-4 text-lg">
        <li class="hover:underline">
          <a href="{base}/intro">Intro</a>
        </li>
        <li class="hover:underline">
          <a href="{base}/demo">Demo</a>
        </li>
        <li class="hover:underline">
          <a href="{base}/developer">Developer</a>
        </li>
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
    </div>
  </div>
</nav>

<nav class="bg-gray-100 py-5">
  <div class="max-w-7xl mx-auto px-4">
    <div class="items-center flex justify-between">
      <!-- leftside -->
      <div class="flex space-x-4">
        <!-- mobile menu -->
        <button
          class="lg:hidden"
          onclick={openMobileMenu}
          aria-label="Open mobile menu"
        >
          <svg viewBox="0 0 24 24" class="w-4 h-4">
            <path
              fill="none"
              stroke="currentColor"
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M4 6h16M4 12h16M4 18h16"
            />
          </svg>
        </button>

        <!-- logo (shown on large screens) -->
        <div class="hidden lg:block">
          <NavbarLogo />
        </div>
      </div>

      <!-- middle -->
      <div class="flex items-center space-x-1">
        <!-- logo -->
        <div class="block lg:hidden">
          <NavbarLogo />
        </div>

        <!-- primary nav -->
        <div class="hidden lg:block">
          <a href="{base}/intro" class="px-3 text-gray-700 hover:text-gray-900"
            >Intro</a
          >
          <a href="{base}/demo" class="px-3 text-gray-700 hover:text-gray-900"
            >Demo</a
          >
          <a
            href="{base}/developer"
            class="px-3 text-gray-700 hover:text-gray-900">Developer</a
          >
        </div>
      </div>

      <!-- right side -->
      <div class="flex items-center space-x-1">
        <a href="https://github.com/jokk-itu/authserver" target="_blank">
          <img
            src="{base}/github.svg"
            alt="Github"
            height="20px"
            width="20px"
          />
        </a>
      </div>
    </div>
  </div>
</nav>
