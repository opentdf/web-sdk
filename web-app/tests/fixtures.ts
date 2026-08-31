import { mkdirSync, writeFileSync } from 'node:fs';
import { test as base } from '@playwright/test';

const collectCoverage = !!process.env.COVERAGE;
const coverageDir = new URL('../.nyc_output/', import.meta.url);
let coverageFiles = 0;

/**
 * `test` with an automatic fixture that saves browser coverage after each test.
 * Specs import from here rather than from '@playwright/test'; there is nothing
 * else for a spec, or a new test in one, to remember to do.
 */
export const test = base.extend<{ browserCoverage: void }>({
  browserCoverage: [
    async ({ page }, use, testInfo) => {
      await use();
      if (!collectCoverage || page.isClosed()) {
        return;
      }
      // Coverage counters live on the page and reset on navigation, so this captures
      // the last navigation of the test.
      const data = await page.evaluate(
        () => (globalThis as { __coverage__?: unknown }).__coverage__
      );
      if (!data) {
        throw new Error('COVERAGE is set but window.__coverage__ is missing on ' + page.url());
      }
      mkdirSync(coverageDir, { recursive: true });
      const name = `roundtrip-${testInfo.project.name}-${testInfo.workerIndex}-${coverageFiles++}`;
      writeFileSync(new URL(`${name}.json`, coverageDir), JSON.stringify(data));
    },
    { auto: true },
  ],
});

export { expect } from '@playwright/test';
