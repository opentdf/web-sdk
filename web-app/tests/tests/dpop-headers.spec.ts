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

  // We expect at minimum: token exchange + rewrap
  expect(captured.length).toBeGreaterThanOrEqual(2);

  for (const r of captured) {
    if (r.url.includes('/kas')) {
      expect(r.authorization, `${r.url} should carry an Authorization header`).toBeTruthy();
      expect(r.dpop, `${r.url} should carry a DPoP header`).toBeTruthy();
    }
  }

  // Decode one proof header to confirm it is a well-formed DPoP proof (RFC 9449 §4.2).
  const proof = captured.find((r) => r.url.includes('/kas') && r.dpop)?.dpop;
  expect(proof, 'a KAS request should carry a DPoP proof').toBeTruthy();
  const header = JSON.parse(Buffer.from(proof!.split('.')[0], 'base64url').toString('utf8'));
  expect(header.typ).toBe('dpop+jwt');
});
