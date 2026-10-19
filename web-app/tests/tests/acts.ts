import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { Download, Page } from '@playwright/test';

export const appUrl = 'http://localhost:65432/';

export const authorize = async (page: Page) => {
  await page.goto(appUrl);
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

/**
 * Where a finished download landed. Stock Firefox (playwright.moz-firefox.config.ts)
 * ignores Playwright's download folder and saves under the suggested name in
 * PLAYWRIGHT_DOWNLOAD_DIR instead, so `download.path()` names a missing file.
 */
export const downloadPath = async (download: Download): Promise<string> => {
  const reported = await download.path();
  if (existsSync(reported)) {
    return reported;
  }
  const dir = process.env.PLAYWRIGHT_DOWNLOAD_DIR;
  const saved = dir && join(dir, download.suggestedFilename());
  if (!saved || !existsSync(saved)) {
    throw new Error(`Download ${download.suggestedFilename()} is not at ${reported} or ${saved}`);
  }
  return saved;
};

export const loadFile = async (page: Page, path: string) => {
  await page.locator('#fileSelector').setInputFiles(path);
};
