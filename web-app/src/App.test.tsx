import { afterAll, beforeAll, describe, test } from 'vitest';
import { preview, type PreviewServer } from 'vite';
import { chromium, type Browser, type Page } from 'playwright';
import { expect } from '@playwright/test';

describe('basic', () => {
  let server: PreviewServer;
  let browser: Browser;
  let page: Page;

  beforeAll(async () => {
    server = await preview({ preview: { port: 3000 } });
    browser = await chromium.launch();
    page = await browser.newPage();
  });

  afterAll(async () => {
    await browser.close();
    await new Promise<void>((resolve, reject) => {
      server.httpServer.close((error) => (error ? reject(error) : resolve()));
    });
  });

  test('starts logged out', async () => {
    await page.goto('http://localhost:3000');
    const sessionState = page.locator('#sessionState');
    expect(sessionState).toHaveText('start');
  }, 60_000);

  test('file upload check', async () => {
    await page.goto('http://localhost:3000');
    await page.locator('#fileSelector').setInputFiles('index.html');
    await page.locator('text=index.html').click();

    const details = page.locator('#details');
    await expect(details).toContainText('index.html');
    await expect(details).toContainText('Content Type: text/html');
  }, 15_000);
});
