import { afterAll, beforeAll, describe, test } from 'vitest';
import { preview } from 'vite';
import type { PreviewServer } from 'vite';
import { chromium } from 'playwright';
import type { Browser, Page } from 'playwright';
import { expect } from '@playwright/test';

describe('basic', async () => {
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

  test('count the clicker', async () => {
    await page.goto('http://localhost:3000');
    const button = page.locator('#clicker');
    expect(button).toBeDefined();

    await expect(button).toHaveText('Click count is 0');

    await button.click();
    await expect(button).toHaveText('Click count is 1');
  }, 60_000);

  test('file upload check', async () => {
    await page.goto('http://localhost:3000');
    const [fileChooser] = await Promise.all([
      // It is important to call waitForEvent before click to set up waiting.
      page.waitForEvent('filechooser'),
      // Opens the file chooser.
      page.locator('#file-selector').click(),
    ]);
    await fileChooser.setFiles('index.html');
    await page.locator('text=index.html').click();

    const details = page.locator('#details');
    await expect(details).toContainText('index.html');
    await expect(details).toContainText('Content Type: text/html');

    const processButton = page.locator('#process');
    await processButton.click();

    const segments = page.locator('#segments');
    expect(segments).toBeDefined();
    await expect(segments).toContainText('Starting file bytes: 3c21');
  }, 60_000);
});
