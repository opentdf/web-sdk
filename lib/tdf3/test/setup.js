/* eslint-disable no-undef */
import { webcrypto } from 'node:crypto';
import { ReadableStream } from 'node:stream/web';

if (!globalThis.ReadableStream) {
  globalThis.ReadableStream = ReadableStream;
}

globalThis.crypto = webcrypto;
