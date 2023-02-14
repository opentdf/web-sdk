import { type BrowserTdfStream } from './BrowserTdfSteam.js';
import { DecoratedReadableStream } from './DecoratedReadableStream.js';
import { type NodeTdfStream } from './NodeTdfStream.js';

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

export function makeStream(a: ConstructorParameters<AnyTdfStreamCtor>[0]): DecoratedReadableStream {
  if (!_stream.factory) {
    throw Error('Stream factory misconfigured');
  }
  return new _stream.factory(a);
}
