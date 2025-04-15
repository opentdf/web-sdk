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
    await server.close();
  });

  test('starts logged out', async () => {
    await page.goto('http://localhost:3000');
    const sessionState = page.locator('#sessionState');
    await expect(sessionState).toContainText('start');
  }, 60_000);

  test('file upload check', async () => {
    await page.goto('http://localhost:3000');
    await page.locator('#fileSelector').setInputFiles('index.html');
    await page.locator('text=index.html').click();

    const details = page.locator('#details');
    await expect(details).toContainText('index.html');
    await expect(details).toContainText('Content Type: text/html');
  }, 15_000);

  test('connect rpc example', async () => {
    await page.goto('http://localhost:3000');

    let element = await page.locator('#wellknown_config');
    await expect(element).toContainText('Wellknown');

    element = await page.locator('#public_kas_key');
    await expect(element).toContainText('Public Key Kas');

    element = await page.locator('#policy_list_attr');
    await expect(element).toContainText('Policy List Attributes');

    element = await page.locator('#connect_result');
    await expect(element).toHaveValue('');
  }, 15_000);
});
