export { default as Client } from './client';
export * as Errors from './errors';
export { default as TDF } from './tdf';
export { version, clientType } from './version';
import { MockStream } from './utils/mock-stream';

/**
 * Creates a mocked stream which mimicks a Node stream (tdf3-js's stream implementation) to be used
 * when options are limited via a browser. It provides the library with all necessary callbacks and
 * emitters it expects, but loads the entire file data into memory before processing each chunk of data
 * separately.
 * @param streamContent The content to use for a read stream
 * @returns a new mock stream, with a subset of the listener methods available.
 */
export function createMockStream(streamContent?: Uint8Array) {
  return new MockStream(streamContent);
}
