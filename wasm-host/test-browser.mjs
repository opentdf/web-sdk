// test-browser.mjs — Headless Playwright test runner for WASM TDF browser tests.
// Usage: node test-browser.mjs
//
// Starts the dev server, opens test.html in headless Chromium, captures results.

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const ROOT = fileURLToPath(new URL('.', import.meta.url));

const MIME = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.mjs': 'application/javascript',
  '.wasm': 'application/wasm',
  '.json': 'application/json',
};

// Start dev server with COOP/COEP headers
const server = createServer(async (req, res) => {
  const path = join(ROOT, req.url === '/' ? '/test.html' : req.url);
  try {
    const data = await readFile(path);
    res.writeHead(200, {
      'Content-Type': MIME[extname(path)] || 'application/octet-stream',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    });
    res.end(data);
  } catch {
    res.writeHead(404);
    res.end('Not found');
  }
});

await new Promise(resolve => server.listen(0, resolve));
const port = server.address().port;
console.log(`Dev server on http://localhost:${port}`);

// Launch headless browser
const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();

// Capture console output
const logs = [];
page.on('console', msg => {
  const text = msg.text();
  logs.push(text);
  console.log(`[browser] ${text}`);
});

page.on('pageerror', err => {
  console.error(`[browser error] ${err.message}`);
});

try {
  await page.goto(`http://localhost:${port}/test.html`, { waitUntil: 'domcontentloaded' });

  // Wait for test results — look for the "Results:" line in #log
  await page.waitForFunction(() => {
    const log = document.getElementById('log');
    return log && log.textContent.includes('Results:');
  }, { timeout: 30000 });

  // Extract results
  const text = await page.textContent('#log');
  console.log('\n=== Test Output ===');
  console.log(text);

  // Check for failures
  const failMatch = text.match(/(\d+) failed/);
  const failures = failMatch ? parseInt(failMatch[1]) : 0;
  process.exitCode = failures > 0 ? 1 : 0;
} catch (err) {
  console.error(`Test failed: ${err.message}`);
  process.exitCode = 1;
} finally {
  await browser.close();
  server.close();
}
