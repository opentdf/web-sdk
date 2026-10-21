import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import { expect, type Download, type Page } from '@playwright/test';

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
 * Where a finished download landed, after checking which way it was saved. The
 * in-memory Blob fallback writes the same bytes as the service worker, so
 * without this check a broken worker would go unnoticed.
 *
 * Stock Firefox (playwright.moz-firefox.config.ts) ignores Playwright's download
 * folder and saves under the suggested name in PLAYWRIGHT_DOWNLOAD_DIR, so
 * `download.path()` names a missing file. It would save a later download with
 * the same name as `name(1).ext`, so each file is moved into a folder of its
 * own once found. That relies on one download at a time, so that config runs
 * one test at a time (`workers: 1`).
 */
export const downloadPath = async (
  download: Download,
  via: 'service-worker' | 'blob' = 'service-worker'
): Promise<string> => {
  expect(download.url()).toContain(via === 'blob' ? 'blob:' : '/__download__/');
  const reported = await download.path();
  if (existsSync(reported)) {
    return reported;
  }
  const dir = process.env.PLAYWRIGHT_DOWNLOAD_DIR;
  const name = download.suggestedFilename();
  const saved = dir && join(dir, name);
  if (!dir || !saved || !existsSync(saved)) {
    throw new Error(`Download ${name} is not at ${reported} or ${saved}`);
  }
  const claimed = join(dir, 'claimed', randomUUID());
  mkdirSync(claimed, { recursive: true });
  renameSync(saved, join(claimed, name));
  return join(claimed, name);
};

export const loadFile = async (page: Page, path: string) => {
  await page.locator('#fileSelector').setInputFiles(path);
};
