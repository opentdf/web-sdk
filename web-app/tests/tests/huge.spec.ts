import type { Page } from '@playwright/test';
import { test, expect } from '../fixtures.js';
import fs from 'node:fs';
import { appUrl, authorize, downloadPath, loadFile } from './acts.js';

test.beforeEach(async ({ page }) => {
  page.on('pageerror', (err) => {
    console.error(err);
  });
  page.on('console', (message) => {
    console.log(message);
  });
});

// Playwright's patched Firefox keeps a copy of every response body, downloads
// included, in its parent process, so these sizes exhaust memory (DSPX-5084).
// Run Firefox with playwright.moz-firefox.config.ts instead, which drives
// stock Firefox.
test.skip(
  ({ browserName }) => browserName === 'firefox',
  "Playwright's Firefox buffers downloads in memory; use playwright.moz-firefox.config.ts"
);

const GiB = 2 ** 30;

// 2^32 is where zip64 sizes and offsets stop fitting in 32 bits; odd sizes
// also leave a partial final segment.
const sizes = [
  { name: '3 GiB', bytes: 3 * GiB },
  { name: 'just under 4 GiB', bytes: 2 ** 32 - 1 },
  { name: 'just over 4 GiB', bytes: 2 ** 32 + 1 },
  { name: '5 GiB', bytes: 5 * GiB },
];

for (const { name, bytes } of sizes) {
  test(`Large File: ${name}`, async ({ page }) => {
    await authorize(page);
    await page.goto(`${appUrl}?segmentBatchSize=2&maxConcurrentSegmentBatches=1`);
    await expect(page.locator('#sessionState')).toHaveText('loggedin');

    const decryptTuningLogs: string[] = [];
    page.on('console', (message) => {
      const text = message.text();
      if (text.includes('Using decrypt read tuning')) {
        decryptTuningLogs.push(text);
      }
    });

    await page.locator('#randomSelector').fill(bytes.toString());

    const downloadPromise = page.waitForEvent('download');
    await page.locator('#fileSink').click();
    await page.locator('#encryptButton').click();

    const download = await downloadPromise;
    const cipherTextPath = await downloadPath(download);
    try {
      expect(download.suggestedFilename()).toContain('bytes');
      expect(cipherTextPath).toBeTruthy();
      if (!cipherTextPath) {
        throw new Error();
      }

      await page.locator('#randomSelector').clear();
      await loadFile(page, cipherTextPath);
      const plainDownloadPromise = page.waitForEvent('download', { timeout: 60000 });
      await page.locator('#fileSink').click();
      await page.locator('#decryptButton').click();
      const download2 = await plainDownloadPromise;
      expect(download2.suggestedFilename()).toContain('.decrypted');
      expect(decryptTuningLogs).toEqual([
        'Using decrypt read tuning {"segmentBatchSize":2,"maxConcurrentSegmentBatches":1}',
      ]);
      const plainTextPath = await downloadPath(download2);
      if (!plainTextPath) {
        throw new Error();
      }
      try {
        const stats = fs.statSync(plainTextPath);
        expect(stats).toHaveProperty('size', bytes);
      } finally {
        plainTextPath && fs.unlinkSync(plainTextPath);
      }
    } finally {
      cipherTextPath && fs.unlinkSync(cipherTextPath);
    }
  });
}
