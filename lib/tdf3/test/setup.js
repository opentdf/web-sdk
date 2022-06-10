import {
  ReadableStream
} from 'node:stream/web';
if (!global.ReadableStream ) {
  global.ReadableStream = ReadableStream;
}
