import { defineConfig } from 'vite';

// Why a bare config: this is a static, dependency-free app. We do not need
// framework plugins, proxies, or env injection. Keeping this file empty-ish
// is itself a privacy statement: nothing reaches out anywhere at build time.
export default defineConfig({
  root: '.',
  base: './',
  build: {
    outDir: 'dist',
    sourcemap: true,
    // Vite's default modulepreload polyfill calls fetch() in the bundle.
    // We target modern browsers (native <link rel="modulepreload">), so the
    // polyfill is unnecessary - and leaving it in would put a network-capable
    // API into a bundle that claims to be network-free. Our privacy static
    // scan (scripts/privacy-check.mjs) caught exactly this; disabling the
    // polyfill is the honest fix, rather than allow-listing the fetch() call.
    modulePreload: { polyfill: false },
    // Fail loudly rather than silently inlining something huge we didn't expect.
    chunkSizeWarningLimit: 300
  },
  server: {
    // No proxy, no CORS tunnel to anywhere - local dev only.
    port: 5173
  }
});
