import { test, expect } from '../fixtures.js';
import fs from 'node:fs';
import { readFile } from 'node:fs/promises';
import { serve } from '../static-server.js';
import { authorize, loadFile } from './acts.js';

// References
// Playwright assertions: https://playwright.dev/docs/test-assertions
// upload files: https://timdeschryver.dev/blog/how-to-upload-files-with-playwright

test.beforeEach(async ({ page }) => {
  page.on('pageerror', (err) => {
    console.error(err);
  });
  page.on('console', (message) => {
    console.log(message);
  });
});

test('login', async ({ page }) => {
  await authorize(page);
  await expect(page).toHaveTitle(/opentdf browser sample/);
  await expect(page.locator('#user_token')).toHaveText(/accessToken/);
});

test('roundtrip ztdf', async ({ page }) => {
  page.on('download', (download) =>
    download.path().then((r) => console.log(`Saves ${download.suggestedFilename()} as ${r}`))
  );

  await authorize(page);
  await loadFile(page, 'README.md');
  const downloadPromise = page.waitForEvent('download');
  await page.locator('#fileSink').click();
  await page.locator('#encryptButton').click();
  const download = await downloadPromise;
  // Encrypt tags the container with the default wrap algorithm.
  expect(download.suggestedFilename()).toContain('README.md-ecsecp256r1');
  const cipherTextPath = await download.path();
  expect(cipherTextPath).toBeTruthy();
  if (!cipherTextPath) {
    throw new Error();
  }

  // Clear file selector and upload again
  await page.locator('#clearFile').click();
  await loadFile(page, cipherTextPath);
  const plainDownloadPromise = page.waitForEvent('download');
  await page.locator('#fileSink').click();
  await page.locator('#decryptButton').click();
  const download2 = await plainDownloadPromise;
  expect(download2.suggestedFilename()).toContain('.decrypted');
  const plainTextPath = await download2.path();
  if (!plainTextPath) {
    throw new Error();
  }
  const text = await readFile(plainTextPath, 'utf8');
  expect(text, `Looking for clone command in ${plainTextPath}`).toContain(
    'try encrypting some of your own files'
  );
});

// ML-KEM-512 is intentionally omitted: the platform KAS only supports mlkem:768
// and mlkem:1024 (see lib/ocrypto/key_type.go), so a 512 roundtrip cannot rewrap.
for (const algorithm of ['mlkem:768', 'mlkem:1024'] as const) {
  const expectedKid = algorithm.replace(':', '');
  const expectedWrappedKeyBytes = algorithm === 'mlkem:768' ? 1158 : 1638;
  test(`roundtrip ztdf with ${algorithm}`, async ({ page }) => {
    page.on('download', (download) =>
      download.path().then((r) => console.log(`Saves ${download.suggestedFilename()} as ${r}`))
    );

    await authorize(page);
    await loadFile(page, 'README.md');
    // Both legs post-quantum: the KAO wrap on encrypt, and the client's
    // ephemeral key for the rewrap exchange on decrypt.
    await page.locator('#encapAlgorithm').selectOption(algorithm);
    await page.locator('#rewrapAlgorithm').selectOption(algorithm);

    const downloadPromise = page.waitForEvent('download');
    await page.locator('#fileSink').click();
    await page.locator('#encryptButton').click();
    const download = await downloadPromise;
    // The wrap qualifier is the algorithm token without its colon, which for
    // ML-KEM is also the KAS kid.
    expect(download.suggestedFilename()).toContain(`README.md-${expectedKid}`);
    const cipherTextPath = await download.path();
    expect(cipherTextPath).toBeTruthy();
    if (!cipherTextPath) {
      throw new Error();
    }

    // The inspector is populated straight off the encrypt manifest, so the
    // chosen wrap algorithm is observable without decrypting first.
    await expect(page.locator('#kao-kid-0')).toHaveText(expectedKid);
    await expect(page.locator('#kao-type-0')).toHaveText('mlkem-wrapped');
    await expect(page.locator('#kao-wrapped-bytes-0')).toHaveText(String(expectedWrappedKeyBytes));

    await page.locator('#clearFile').click();
    // Clearing the file clears the inspector with it. Without this the decrypt
    // assertions below could be satisfied by leftover encrypt-side state: both
    // legs read the same manifest, so they expect identical values.
    await expect(page.locator('#kaoMetadata')).toBeHidden();

    await loadFile(page, cipherTextPath);
    const plainDownloadPromise = page.waitForEvent('download');
    await page.locator('#fileSink').click();
    await page.locator('#decryptButton').click();
    const download2 = await plainDownloadPromise;
    expect(download2.suggestedFilename()).toContain('.decrypted');
    const plainTextPath = await download2.path();
    if (!plainTextPath) {
      throw new Error();
    }
    const text = await readFile(plainTextPath, 'utf8');
    expect(text, `Looking for clone command in ${plainTextPath}`).toContain(
      'try encrypting some of your own files'
    );

    // Repopulated by the decrypt-side read. The panel was asserted empty after
    // #clearFile above, so these cannot be the encrypt-side values lingering.
    await expect(page.locator('#kao-kid-0')).toHaveText(expectedKid);
    await expect(page.locator('#kao-type-0')).toHaveText('mlkem-wrapped');
    await expect(page.locator('#kao-wrapped-bytes-0')).toHaveText(String(expectedWrappedKeyBytes));
  });
}

test('download names record both key wrap legs', async ({ page }) => {
  await authorize(page);
  await loadFile(page, 'README.md');
  await page.locator('#encapAlgorithm').selectOption('mlkem:768');

  const downloadPromise = page.waitForEvent('download');
  await page.locator('#fileSink').click();
  await page.locator('#encryptButton').click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe('README.md-mlkem768.tdf');
  const cipherTextPath = await download.path();
  if (!cipherTextPath) {
    throw new Error();
  }

  // Re-upload under the name encrypt suggested. The other tests hand back
  // playwright's temp uuid, which has no `.tdf` suffix, so they only ever reach
  // the parser's no-match fallback and never its successful-parse branch.
  const staged = test.info().outputPath(download.suggestedFilename());
  fs.copyFileSync(cipherTextPath, staged);

  await page.locator('#clearFile').click();
  await loadFile(page, staged);
  await page.locator('#rewrapAlgorithm').selectOption('mlkem:1024');

  const plainDownloadPromise = page.waitForEvent('download');
  await page.locator('#fileSink').click();
  await page.locator('#decryptButton').click();
  const download2 = await plainDownloadPromise;
  // Wrap qualifier is carried through; the rewrap mechanism is appended.
  expect(download2.suggestedFilename()).toBe('README-mlkem768-rwk-p=mlkem1024.decrypted.md');

  // The download event fires when the stream opens, not when it finishes, so the
  // name alone would still be asserted had the mlkem:768 -> mlkem:1024 rewrap
  // failed partway. Read the bytes back to pin that the exchange completed.
  const plainTextPath = await download2.path();
  if (!plainTextPath) {
    throw new Error();
  }
  const text = await readFile(plainTextPath, 'utf8');
  expect(text).toContain('try encrypting some of your own files');
});

test('changing the source retires the previous output', async ({ page }) => {
  await authorize(page);
  // Random bytes rather than a url source: this needs no static server, and the
  // `Clear file` button that used to be the only reset path is not rendered for
  // a non-file source, which is exactly the hole being covered.
  await page.locator('#noneSink').click();
  await page.locator('#randomSelector').fill('1024');
  await page.locator('#encryptButton').click();

  await expect(page.locator('#downloadState')).toContainText('Complete');
  await expect(page.locator('#kaoMetadata')).toBeVisible();

  await page.locator('#randomSelector').fill('2048');
  // Nothing has been encrypted from the new source, so a status or an inspector
  // here would be describing the previous one.
  await expect(page.locator('#downloadState')).toBeHidden();
  await expect(page.locator('#kaoMetadata')).toBeHidden();
});

test('Remote Source Streaming', async ({ page }) => {
  const server = await serve('.', 8086);

  try {
    await authorize(page);
    await page.locator('#urlSelector').fill('http://localhost:8086/README.md');

    const downloadPromise = page.waitForEvent('download');
    await page.locator('#fileSink').click();
    await page.locator('#encryptButton').click();

    const download = await downloadPromise;
    const cipherTextPath = await download.path();
    expect(download.suggestedFilename()).toContain('README.md-ecsecp256r1');
    expect(cipherTextPath).toBeTruthy();
    if (!cipherTextPath) {
      throw new Error();
    }

    const dirname = new URL('.', import.meta.url).pathname;
    const targetPath = `${dirname}/../README.md.tdf`;
    console.log(`cp ${cipherTextPath} ${targetPath}`);
    fs.copyFileSync(cipherTextPath, targetPath);

    // Clear file selector and upload again
    await page.locator('#urlSelector').fill('http://localhost:8086/README.md.tdf');
    const plainDownloadPromise = page.waitForEvent('download');
    await page.locator('#fileSink').click();
    await page.locator('#decryptButton').click();
    const download2 = await plainDownloadPromise;
    const plainTextPath = await download2.path();
    if (!plainTextPath) {
      throw new Error();
    }
    expect(download2.suggestedFilename()).toContain('.decrypted');
    const text = await readFile(plainTextPath, 'utf8');
    expect(text).toContain('try encrypting some of your own files');
  } finally {
    server.close();
  }
});
