import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // jsdom is required because Section 5.4 header/HTML parsing uses
    // DOMParser, and we test that in Node via Vitest, not only in a browser.
    environment: 'jsdom',
    include: ['tests/**/*.test.ts', 'src/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reportsDirectory: './coverage',
      // The core engine (src/core) is what we actually grade ourselves on;
      // UI coverage is tracked separately via Playwright, not unit coverage.
      include: ['src/core/**']
    }
  }
});
