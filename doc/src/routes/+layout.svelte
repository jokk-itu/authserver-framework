<script>
    import "../app.css";
    import Navbar from "../components/Navbar.svelte";
    import Footer from "../components/Footer.svelte";
</script>

<Navbar />
<main class="container px-4 sm:mx-auto mt-8">
    <div class="w-full">
        <slot />
    </div>
</main>
<Footer />