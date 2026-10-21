import { mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import base from './playwright.config.js';

/**
 * Runs the suite on stock Firefox (/Applications/Firefox.app, /snap/bin/firefox)
 * over WebDriver BiDi, which Playwright supports experimentally:
 *
 *   PLAYWRIGHT_TESTS_TO_RUN=huge npx playwright test -c playwright.moz-firefox.config.ts
 *
 * Playwright's own patched Firefox keeps a copy of every response body in its
 * parent process, so a multi-GiB download exhausts memory however the page
 * produces it. Under BiDi, memory still grows with each download, because
 * Playwright registers a network data collector for response bodies. Firefox
 * itself streams these downloads to disk with flat memory when no automation
 * is attached. So this runs huge.spec.ts on a workstation with RAM to spare,
 * but not on a CI runner.
 *
 * Stock Firefox ignores Playwright's download folder, so point it at one we
 * know; downloadPath() in tests/acts.ts looks there. Downloads are found by
 * name, so run one test at a time.
 */
const downloadDir = join(tmpdir(), 'playwright-moz-firefox-downloads');
process.env.PLAYWRIGHT_DOWNLOAD_DIR = downloadDir;
// Workers load this file too; only the main process may clear the folder.
if (!process.env.TEST_WORKER_INDEX) {
  rmSync(downloadDir, { recursive: true, force: true });
}
mkdirSync(downloadDir, { recursive: true });

export default {
  ...base,
  workers: 1,
  projects: [
    {
      name: 'moz-firefox',
      use: {
        browserName: '_bidiFirefox',
        channel: 'moz-firefox',
        launchOptions: {
          firefoxUserPrefs: {
            'browser.download.dir': downloadDir,
            'browser.download.folderList': 2,
            'browser.download.useDownloadDir': true,
          },
        },
      },
    },
  ],
};
