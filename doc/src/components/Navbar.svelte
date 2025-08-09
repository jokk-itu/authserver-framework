<script lang="ts">
  import { base } from "$app/paths";
  import NavbarLogo from "./NavbarLogo.svelte";
  import {developerLinks, navLinks} from '../links'

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
  <div class="w-full h-fit max-w-80 bg-zinc-200">
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
        {#each navLinks as navLink}
          <li class="hover:underline">
            <a href="{navLink.Href}">{navLink.Name}</a>
          </li>
        {/each}
        {#each developerLinks as developerLink}
          <li class="hover:underline">
            <a href="{developerLink.Href}">{developerLink.Name}</a>
          </li>
        {/each}
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
          {#each navLinks as navLink}
          <a href="{navLink.Href}" class="px-3 text-gray-700 hover:text-gray-900">{navLink.Name}</a>
          {/each}
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
