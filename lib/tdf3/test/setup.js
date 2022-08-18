/* eslint-disable no-undef */
import { webcrypto } from 'node:crypto';
import { ReadableStream } from 'node:stream/web';

if (typeof globalThis.ReadableStream === 'undefined') {
  globalThis.ReadableStream = ReadableStream;
}

if (typeof globalThis.crypto === 'undefined') {
  globalThis.crypto = webcrypto;
}
