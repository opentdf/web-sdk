/* eslint-disable no-undef */
import { webcrypto } from 'crypto';
import { ReadableStream } from 'stream/web';
import { registerModuleType } from '../src/client/tdf-stream.js';
import { NodeTdfStream } from '../src/client/NodeTdfStream.js';

if (typeof globalThis.ReadableStream === 'undefined') {
  globalThis.ReadableStream = ReadableStream;
}

if (typeof globalThis.crypto === 'undefined') {
  globalThis.crypto = webcrypto;
}
registerModuleType(NodeTdfStream);
