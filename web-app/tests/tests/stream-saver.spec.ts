import { test, expect, type Page } from '@playwright/test';
import fs from 'node:fs';
import { authorize } from './acts.js';
import { downloadReadableStream } from '../../src/utils/download-readable-stream.js';

test.beforeEach(async ({ page }) => {
  page.on('pageerror', (err) => {
    console.error(err);
  });
  page.on('console', (message) => {
    console.log(message);
  });
});

test('Download readable stream', async ({ page }) => {
  await authorize(page);
  const oneGig = new Uint8Array(1024 * 1024 * 1024);
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(oneGig);
      controller.close();
    },
  });

  let error;
  try {
    await downloadReadableStream(stream, 'file.txt');
  } catch (e) {
    error = e;
  }
  expect(error).toBeUndefined();
});
