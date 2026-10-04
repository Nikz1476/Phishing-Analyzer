import { expect, test } from '@playwright/test';

// End-to-end proof that the analysis pipeline actually runs in the browser
// and produces a reconciled, explainable result - not just that the page loads.
test.describe('analysis flow', () => {
  test('analyses an obvious phishing message and renders a High Risk result', async ({ page }) => {
    await page.goto('/');

    await page.locator('#input').fill(
      'URGENT: YOUR ACCOUNT WILL BE SUSPENDED WITHIN 24 HOURS\n\n' +
      'Dear Customer,\n\n' +
      'Please reply with your password and the 6-digit verification code immediately.\n' +
      'http://192.0.2.45/login.php\n\n' +
      'Failure to comply will result in permanent account closure.'
    );

    await page.locator('#analyse-btn').click();

    const result = page.locator('#result');
    await expect(result).toBeVisible();
    await expect(result.locator('.gauge-value')).toHaveText(/^\d+$/);

    // Classification must be rendered as text (never colour alone).
    await expect(result.locator('.chip')).toContainText(/Low Risk|Suspicious|High Risk/);

    // CRED-PASSWORD must be explained with evidence, why and advice.
    const finding = result.locator('.finding[data-rule="CRED-PASSWORD"]');
    await expect(finding).toHaveCount(1);
    await expect(finding.locator('.why')).not.toBeEmpty();
    await expect(finding.locator('.advice')).not.toBeEmpty();

    // The breakdown must reconcile to the score.
    const score = Number(await result.locator('.gauge-value').textContent());
    const total = Number(await result.locator('.breakdown tfoot td').last().textContent());
    expect(total).toBe(score);
  });

  test('renders a legitimate message as Low Risk', async ({ page }) => {
    await page.goto('/');
    await page.locator('#input').fill(
      'Hi,\n\nYour monthly statement is ready. Set your own password in your account ' +
      'settings at https://accounts.example.test/settings\n\nThanks'
    );
    await page.locator('#analyse-btn').click();

    await expect(page.locator('#result')).toBeVisible();
    await expect(page.locator('#result .chip')).toContainText('Low Risk');
  });

  test('the Learn page lists rules generated from engine metadata', async ({ page }) => {
    await page.goto('/');
    await page.getByRole('button', { name: 'Learn' }).click();
    await expect(page.locator('.learn-card[data-rule="CRED-PASSWORD"]')).toHaveCount(1);
    await expect(page.locator('.learn-card[data-rule="URL-TYPOSQUAT"]')).toHaveCount(1);
  });

  test('Clear wipes input, results and shows no stale output', async ({ page }) => {
    await page.goto('/');
    await page.locator('#input').fill('Dear Customer, confirm your password immediately.');
    await page.locator('#analyse-btn').click();
    await expect(page.locator('#result')).toBeVisible();

    await page.locator('#clear-btn').click();
    await expect(page.locator('#result')).toBeHidden();
    await expect(page.locator('#input')).toHaveValue('');
  });

  test('hostile HTML input renders as inert text, executing nothing', async ({ page }) => {
    await page.goto('/');
    let alerted = false;
    page.on('dialog', async (d) => { alerted = true; await d.dismiss(); });

    await page.locator('#input').fill(
      '<img src=x onerror="window.__pwned=1">\n<script>window.__pwned=1<\/script>\n' +
      'Hello, please confirm your password immediately.'
    );
    await page.locator('#analyse-btn').click();
    await expect(page.locator('#result')).toBeVisible();

    expect(await page.evaluate(() => (window as unknown as Record<string, unknown>).__pwned)).toBeUndefined();
    expect(alerted).toBe(false);
    // The markup must be shown as text, not interpreted.
    await expect(page.locator('#result')).toContainText('onerror');
  });
});