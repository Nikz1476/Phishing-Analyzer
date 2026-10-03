import { expect, test } from '@playwright/test';

// Section 12.8: prove, not just claim, that the built site (a) never makes a
// network request even when the network is physically blocked, and (b) ships
// the CSP meta tag with connect-src 'none'. This runs against the built
// `dist/` output via `vite preview`, never the dev server, so it reflects
// exactly what a real visitor would get.
test.describe('privacy guarantees', () => {
  test('page loads and works with all network requests blocked', async ({ page, context }) => {
    let blockedRequestCount = 0;
    await context.route('**/*', (route) => {
      const url = route.request().url();
      if (url.startsWith('http://127.0.0.1:4173') || url.startsWith('http://localhost:4173')) {
        route.continue();
      } else {
        blockedRequestCount += 1;
        route.abort();
      }
    });

    await page.goto('/');
    await expect(page.locator('h1')).toHaveText('Phishing Email Analyser');
    expect(blockedRequestCount).toBe(0);
  });

  test('CSP meta tag is present and blocks outbound connections', async ({ page }) => {
    await page.goto('/');
    const csp = await page.locator('meta[http-equiv="Content-Security-Policy"]').getAttribute('content');
    expect(csp).toContain("connect-src 'none'");
    expect(csp).toContain("default-src 'none'");
  });

  test('referrer policy meta tag is present', async ({ page }) => {
    await page.goto('/');
    const referrer = await page.locator('meta[name="referrer"]').getAttribute('content');
    expect(referrer).toBe('no-referrer');
  });
});
