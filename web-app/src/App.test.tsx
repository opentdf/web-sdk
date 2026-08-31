import { mkdirSync, writeFileSync } from 'node:fs';
import { afterAll, afterEach, beforeAll, describe, test } from 'vitest';
import { preview, type PreviewServer } from 'vite';
import { chromium, type Browser, type Page } from 'playwright';
import { expect } from '@playwright/test';

// These tests drive a real Chromium against a real build, so nothing they
// exercise is visible to vitest's own v8 coverage provider -- that instruments
// this Node process, not the browser. When COVERAGE is set, vite.config.ts
// instruments the bundle with istanbul instead and the browser accumulates
// counters on `window.__coverage__`; we ship them to .nyc_output for
// `npm run coverage:browser` to turn into lcov.
const collectCoverage = !!process.env.COVERAGE;
const coverageDir = new URL('../.nyc_output/', import.meta.url);
let coverageFiles = 0;

async function saveCoverage(page: Page): Promise<void> {
  if (!collectCoverage) {
    return;
  }
  const data = await page.evaluate(() => (globalThis as { __coverage__?: unknown }).__coverage__);
  if (!data) {
    // Silence here would look exactly like "the app ran but covered nothing",
    // which is the failure this whole setup exists to rule out.
    throw new Error('COVERAGE is set but window.__coverage__ is missing; is the build stale?');
  }
  mkdirSync(coverageDir, { recursive: true });
  writeFileSync(new URL(`vitest-${coverageFiles++}.json`, coverageDir), JSON.stringify(data));
}

describe('basic', () => {
  let server: PreviewServer;
  let browser: Browser;
  let page: Page;

  beforeAll(async () => {
    server = await preview({ preview: { port: 3000 } });
    browser = await chromium.launch();
    page = await browser.newPage();
  });

  // Each test navigates afresh, which resets the counters, so collect per test
  // rather than once at the end. nyc merges the fragments additively.
  afterEach(async () => {
    await saveCoverage(page);
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
});
