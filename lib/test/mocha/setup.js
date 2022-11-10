/* eslint-disable no-undef */
import { webcrypto } from 'crypto';
import { ReadableStream } from 'stream/web';

if (typeof globalThis.ReadableStream === 'undefined') {
  globalThis.ReadableStream = ReadableStream;
}

if (typeof globalThis.crypto === 'undefined') {
  globalThis.crypto = webcrypto;
}

import { registerModuleType } from '../../tdf3/src/client/tdf-stream.js';
import { NodeTdfStream } from '../../tdf3/src/client/NodeTdfStream.js';
registerModuleType(NodeTdfStream);
