import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import { readFile } from 'node:fs/promises';
import { serve } from '../static-server.js';
import { authorize, loadFile } from './acts.js';

// References
// Playwright assertions: https://playwright.dev/docs/test-assertions
// upload files: https://timdeschryver.dev/blog/how-to-upload-files-with-playwright

test.beforeEach(async ({ page }) => {
  page.on('pageerror', (err) => {
    console.error(err);
  });
  page.on('console', (message) => {
    console.log(message);
  });
});

test('login', async ({ page }) => {
  await authorize(page);
  await expect(page).toHaveTitle(/opentdf browser sample/);
  await expect(page.locator('#user_token')).toHaveText(/accessToken/);
});

const scenarios = {
  nano: { encryptSelector: '#nanoEncrypt' },
  tdf: { encryptSelector: '#zipEncrypt' },
};

for (const [name, { encryptSelector }] of Object.entries(scenarios)) {
  test(`roundtrip ${name}`, async ({ page }) => {
    page.on('download', (download) =>
      download.path().then((r) => console.log(`Saves ${download.suggestedFilename()} as ${r}`))
    );

    await authorize(page);
    await loadFile(page, 'README.md');
    const downloadPromise = page.waitForEvent('download');
    await page.locator(encryptSelector).click();
    await page.locator('#fileSink').click();
    await page.locator('#encryptButton').click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('README.md.');
    const cipherTextPath = await download.path();
    expect(cipherTextPath).toBeTruthy();
    if (!cipherTextPath) {
      throw new Error();
    }

    // Clear file selector and upload againg
    await page.locator('#clearFile').click();
    await loadFile(page, cipherTextPath);
    const plainDownloadPromise = page.waitForEvent('download');
    await page.locator('#fileSink').click();
    await page.locator('#decryptButton').click();
    const download2 = await plainDownloadPromise;
    expect(download2.suggestedFilename()).toContain('.decrypted');
    const plainTextPath = await download2.path();
    if (!plainTextPath) {
      throw new Error();
    }
    const text = await readFile(plainTextPath, 'utf8');
    expect(text, `Looking for clone command in ${plainTextPath}`).toContain(
      'try encrypting some of your own files'
    );
  });
}

test('Remote Source Streaming', async ({ page }) => {
  const server = await serve('.', 8086);

  try {
    await authorize(page);
    await page.locator('#urlSelector').fill('http://localhost:8086/README.md');

    const downloadPromise = page.waitForEvent('download');
    await page.locator('#zipEncrypt').click();
    await page.locator('#fileSink').click();
    await page.locator('#encryptButton').click();

    const download = await downloadPromise;
    const cipherTextPath = await download.path();
    expect(download.suggestedFilename()).toContain('README.md.');
    expect(cipherTextPath).toBeTruthy();
    if (!cipherTextPath) {
      throw new Error();
    }

    const dirname = new URL('.', import.meta.url).pathname;
    const targetPath = `${dirname}/../README.md.tdf`;
    console.log(`cp ${cipherTextPath} ${targetPath}`);
    fs.copyFileSync(cipherTextPath, targetPath);

    // Clear file selector and upload againg
    await page.locator('#urlSelector').fill('http://localhost:8086/README.md.tdf');
    const plainDownloadPromise = page.waitForEvent('download');
    await page.locator('#fileSink').click();
    await page.locator('#decryptButton').click();
    const download2 = await plainDownloadPromise;
    const plainTextPath = await download2.path();
    if (!plainTextPath) {
      throw new Error();
    }
    expect(download2.suggestedFilename()).toContain('.decrypted');
    const text = await readFile(plainTextPath, 'utf8');
    expect(text).toContain('try encrypting some of your own files');
  } finally {
    server.close();
  }
});
