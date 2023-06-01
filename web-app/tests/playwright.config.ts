import type { PlaywrightTestConfig } from '@playwright/test';
import { devices } from '@playwright/test';

/**
 * Read environment variables from file.
 * https://github.com/motdotla/dotenv
 */
// require('dotenv').config();

const requestedTests = (process.env.PLAYWRIGHT_TESTS_TO_RUN || 'roundtrip')
  .replace(/[\s,]+/g, ' ')
  .trim()
  .split(' ');
const withHuge = requestedTests.includes('huge');
const testMatch = requestedTests.map((s: string) => `${s}.spec.ts`);

/**
 * See https://playwright.dev/docs/test-configuration.
 */
const config: PlaywrightTestConfig = {
  testDir: './tests',
  testMatch,

  /* Maximum time one test can run for. */
  timeout: withHuge ? 3_600_000 : 10_000,
  expect: {
    timeout: withHuge ? 3_600_000 : 3_000,
  },
  /* Fail the build on CI if you accidentally left test.only in the source code. */
  forbidOnly: !!process.env.CI,
  /* Retry on CI only */
  retries: process.env.CI ? 0 : 0,
  /* Opt out of parallel tests on CI. */
  workers: process.env.CI ? 1 : undefined,
  /* Reporter to use. See https://playwright.dev/docs/test-reporters */
  reporter: 'html',
  /* Shared settings for all the projects below. See https://playwright.dev/docs/api/class-testoptions. */
  use: {
    actionTimeout: 0,
    trace: 'off',
    video: 'off',
  },

  /* Configure projects for major browsers */
  projects: [
    {
      name: 'webkit',
      use: {
        ...devices['Desktop Safari'],
      },
    },
  ],
};

export default config;
