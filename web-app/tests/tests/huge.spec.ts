import { test, expect, type Page } from '@playwright/test';
import fs from 'node:fs';
import { authorize, loadFile } from './acts.js';

test.beforeEach(async ({ page }) => {
  page.on('pageerror', (err) => {
    console.error(err);
  });
  page.on('console', (message) => {
    console.log(message);
  });
});

test('Large File', async ({ page }) => {
  await authorize(page);
  const eightGigs = 2 ** 33;
  await page.locator('#randomSelector').fill(eightGigs.toString());

  const downloadPromise = page.waitForEvent('download');
  await page.locator('#zipEncrypt').click();
  await page.locator('#fileSink').click();
  await page.locator('#encryptButton').click();

  const download = await downloadPromise;
  const cipherTextPath = await download.path();
  expect(download.suggestedFilename()).toContain('bytes');
  expect(cipherTextPath).toBeTruthy();
  if (!cipherTextPath) {
    throw new Error();
  }

  await page.locator('#randomSelector').clear();
  await loadFile(page, cipherTextPath);
  const plainDownloadPromise = page.waitForEvent('download');
  await page.locator('#tdfDecrypt').click();
  await page.locator('#fileSink').click();
  await page.locator('#decryptButton').click();
  const download2 = await plainDownloadPromise;
  expect(download2.suggestedFilename()).toContain('.decrypted');
  const plainTextPath = await download2.path();
  if (!plainTextPath) {
    throw new Error();
  }
  const stats = fs.statSync(plainTextPath);
  expect(stats).toHaveProperty('size', eightGigs);
});
