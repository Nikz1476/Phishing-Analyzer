import { defineConfig } from '@playwright/test';

// Dev-only dependency: Playwright never ships in the built app. It exists
// solely to prove, at build time, that the shipped app makes zero network
// requests (Section 12.8) and that the CSP actually blocks what it claims to.
export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:4173',
    trace: 'retain-on-failure'
  },
  webServer: {
    // --host 127.0.0.1 matters: on Windows `localhost` can resolve to IPv6
    // ::1 while Playwright polls 127.0.0.1, making the readiness probe fail
    // even though the server is up. Binding explicitly removes that mismatch.
    command: 'npm run preview -- --port 4173 --host 127.0.0.1',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000
  }
});
