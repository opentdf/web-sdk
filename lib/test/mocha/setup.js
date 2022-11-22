/* eslint-disable no-undef */
import { webcrypto } from 'crypto';
import { ReadableStream } from 'stream/web';
import { registerModuleType } from '../../tdf3/src/client/tdf-stream';
import { NodeTdfStream } from '../../tdf3/src/client/NodeTdfStream';

if (typeof globalThis.ReadableStream === 'undefined') {
  globalThis.ReadableStream = ReadableStream;
}

if (typeof globalThis.crypto === 'undefined') {
  globalThis.crypto = webcrypto;
}
registerModuleType(NodeTdfStream);
