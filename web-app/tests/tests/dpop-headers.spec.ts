import { test, expect } from '@playwright/test';
import { authorize, loadFile } from './acts.js';

type CapturedRequest = {
  url: string;
  method: string;
  authorization: string | undefined;
  dpop: string | undefined;
};

test('DPoP headers on token and KAS rewrap requests', async ({ page }) => {
  const captured: CapturedRequest[] = [];

  page.on('request', (request) => {
    const url = request.url();
    if (
      url.includes('/protocol/openid-connect/token') ||
      url.includes('/kas.AccessService/Rewrap') ||
      url.includes('/kas/v2/rewrap')
    ) {
      const headers = request.headers();
      captured.push({
        url,
        method: request.method(),
        authorization: headers['authorization'],
        dpop: headers['dpop'],
      });
    }
  });

  page.on('console', (m) => console.log(m.text()));

  await authorize(page);
  await loadFile(page, 'README.md');
  const downloadPromise = page.waitForEvent('download');
  await page.locator('#fileSink').click();
  await page.locator('#encryptButton').click();
  const enc = await downloadPromise;
  const cipherTextPath = await enc.path();
  if (!cipherTextPath) throw new Error('no cipher');

  await page.locator('#clearFile').click();
  await loadFile(page, cipherTextPath);
  const plainDownloadPromise = page.waitForEvent('download');
  await page.locator('#fileSink').click();
  await page.locator('#decryptButton').click();
  await plainDownloadPromise;

  console.log('\n=== CAPTURED DPoP-RELEVANT REQUESTS ===');
  for (const r of captured) {
    console.log(`\n${r.method} ${r.url}`);
    console.log(`  Authorization: ${r.authorization ?? '(none)'}`);
    console.log(`  DPoP:          ${r.dpop ? r.dpop.slice(0, 80) + '...' : '(none)'}`);
  }

  // We expect at minimum: token exchange + rewrap
  expect(captured.length).toBeGreaterThanOrEqual(2);

  for (const r of captured) {
    if (r.url.includes('/kas')) {
      expect(r.authorization, `${r.url} should carry an Authorization header`).toBeTruthy();
      expect(r.dpop, `${r.url} should carry a DPoP header`).toBeTruthy();
    }
  }
});
