import { type BrowserTdfStream } from './BrowserTdfSteam';
import { DecoratedReadableStream } from './DecoratedReadableStream';
import { type NodeTdfStream } from './NodeTdfStream';

export type AnyTdfStream = BrowserTdfStream | NodeTdfStream;
export type AnyTdfStreamCtor = typeof BrowserTdfStream | typeof NodeTdfStream;

export function isAnyTdfStream(s: unknown): s is AnyTdfStream {
  return (
    typeof (s as AnyTdfStream)?.toBuffer !== 'undefined' &&
    typeof (s as AnyTdfStream)?.toFile !== 'undefined' &&
    typeof (s as AnyTdfStream)?.toString !== 'undefined'
  );
}

const _stream: { factory: AnyTdfStreamCtor | null } = { factory: null };

export function registerModuleType(factory: AnyTdfStreamCtor) {
  _stream.factory = factory;
}

export function makeStream(
  byteLimit: number,
  underlyingSource: UnderlyingSource
): DecoratedReadableStream {
  if (!_stream.factory) {
    throw Error('Stream factory misconfigured');
  }
  return new _stream.factory(byteLimit, underlyingSource);
}
