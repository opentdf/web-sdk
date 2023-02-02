import { test, expect, type Page } from '@playwright/test';
import { readFile } from 'fs/promises';

// References
// Playwright assertions: https://playwright.dev/docs/test-assertions
// upload files: https://timdeschryver.dev/blog/how-to-upload-files-with-playwright

const authorize = async (page: Page) => {
  await page.goto('http://localhost:65432/');
  // If we are logged in, return early.
  const sessionState = await page.locator('#sessionState').textContent();
  if (sessionState === 'loggedin') {
    return;
  }
  if (sessionState !== 'start') {
    throw new Error(`Invalid session state [${sessionState}]`);
  }
  await page.locator('#login_button').click();

  await page.fill('#username', 'user1');
  await page.fill('#password', 'testuser123');
  await page.click('#kc-login');

  await page.waitForResponse('**/token');
};

const loadFile = async (page: Page, path: string) => {
  await page.locator('#fileSelector').setInputFiles(path);
};

test('login', async ({ page }) => {
  await authorize(page);
  await expect(page).toHaveTitle(/opentdf browser sample/);
  await expect(page.locator('#user_token')).toHaveText(/accessToken/);
});

test('nano', async ({ page }) => {
  await authorize(page);
  await loadFile(page, 'README.md');
  const downloadPromise = page.waitForEvent('download');
  await page.locator('#encryptButton').click();
  const download = await downloadPromise;
  const nanoTdfPath = await download.path();
  expect(nanoTdfPath).toBeTruthy();
  if (!nanoTdfPath) {
    throw new Error();
  }

  // Clear file selector and upload againg
  await page.locator('#clearFile').click();
  await loadFile(page, nanoTdfPath);
  const plainDownloadPromise = page.waitForEvent('download');
  await page.locator('#decryptButton').click();
  const download2 = await plainDownloadPromise;
  const plainTextPath = await download2.path();
  if (!plainTextPath) {
    throw new Error();
  }
  const text = await readFile(plainTextPath, 'utf8');
  expect(text).toContain('git clone https://github.com/opentdf/opentdf.git');
});
