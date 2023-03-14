import { test, expect, type Page } from '@playwright/test';
import { readFile } from 'node:fs/promises';
import { serve } from '../static-server.js';

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
  await Promise.all([page.waitForResponse('**/token'), page.click('#kc-login')]);
};

const loadFile = async (page: Page, path: string) => {
  await page.locator('#fileSelector').setInputFiles(path);
};

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
  nano: { encryptSelector: '#nanoEncrypt', decryptSelector: '#nanoDecrypt' },
  tdf: { encryptSelector: '#zipEncrypt', decryptSelector: '#tdfDecrypt' },
  html: { encryptSelector: '#htmlEncrypt', decryptSelector: '#tdfDecrypt' },
};

for (const [name, { encryptSelector, decryptSelector }] of Object.entries(scenarios)) {
  test(name, async ({ page }) => {
    await authorize(page);
    await loadFile(page, 'README.md');
    const downloadPromise = page.waitForEvent('download');
    await page.locator(encryptSelector).click();
    await page.locator('#encryptButton').click();
    const download = await downloadPromise;
    const cipherTextPath = await download.path();
    expect(cipherTextPath).toBeTruthy();
    if (!cipherTextPath) {
      throw new Error();
    }

    // Clear file selector and upload againg
    await page.locator('#clearFile').click();
    await loadFile(page, cipherTextPath);
    const plainDownloadPromise = page.waitForEvent('download');
    await page.locator(decryptSelector).click();
    await page.locator('#decryptButton').click();
    const download2 = await plainDownloadPromise;
    const plainTextPath = await download2.path();
    if (!plainTextPath) {
      throw new Error();
    }
    const text = await readFile(plainTextPath, 'utf8');
    expect(text).toContain('git clone https://github.com/opentdf/opentdf.git');
  });
}

test('Remote Source Streaming', async ({ page }) => {
  const port = 8000;
  const file = 'README.md';
  const server = await serve(port, file);

  try {
    await authorize(page);
    await page.locator('#urlSelector').fill('http://localhost:8000/README.md');
  
    const downloadPromise = page.waitForEvent('download');
    await page.locator('#zipEncrypt').click();
    await page.locator('#encryptButton').click();
  
    const download = await downloadPromise;
    const cipherTextPath = await download.path();
    expect(cipherTextPath).toBeTruthy();
    if (!cipherTextPath) {
      throw new Error();
    }
  
    // Clear file selector and upload againg
    await page.locator('#clearFile').click();
    await loadFile(page, cipherTextPath);
    const plainDownloadPromise = page.waitForEvent('download');
    await page.locator('#tdfDecrypt').click();
    await page.locator('#decryptButton').click();
    const download2 = await plainDownloadPromise;
    const plainTextPath = await download2.path();
    if (!plainTextPath) {
      throw new Error();
    }
    const text = await readFile(plainTextPath, 'utf8');
    expect(text).toContain('git clone https://github.com/opentdf/opentdf.git');
  } finally {
    server.close()
  }
});
