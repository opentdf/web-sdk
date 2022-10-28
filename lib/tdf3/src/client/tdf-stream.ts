// @ts-ignore
import { default as TdfStream } from '@tdfStream';
export { TdfStream }; // webpack alias, check webpack.config.js file

import type BrowserTdfStream from './BrowserTdfSteam';
import type NodeTdfStream from './NodeTdfStream';

export type AnyTdfStream = BrowserTdfStream | NodeTdfStream;

export function isAnyTdfStream(s: unknown): s is AnyTdfStream {
  return s instanceof TdfStream || typeof (s as AnyTdfStream)?.toBuffer !== 'undefined';
}
