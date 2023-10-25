/* eslint-disable no-undef */
import { webcrypto } from 'crypto';
import { ReadableStream } from 'stream/web';
import { JSDOM } from 'jsdom';

if (typeof globalThis.ReadableStream === 'undefined') {
  // @ts-expect-error: ReadableStream not valid
  globalThis.ReadableStream = ReadableStream;
}

if (typeof globalThis.crypto === 'undefined') {
  // @ts-expect-error: crypto not valid
  globalThis.crypto = webcrypto;
}

const jsdom = new JSDOM('<!doctype html><html><body></body></html>');
const { window } = jsdom;

function copyProps(src: string, target: Record<string, unknown>) {
  const props = Object.getOwnPropertyNames(src)
    .filter((prop) => typeof target[prop] === 'undefined')
    .map((prop) => Object.getOwnPropertyDescriptor(src, prop));
  // @ts-expect-error: asdfaj
  Object.defineProperties(target, props);
}

globalThis.document ??= {
  // @ts-expect-error: safda not valid
  createElement: console.log,
  // @ts-expect-error: safda not valid
  documentElement: { style: {} },
};

// @ts-expect-error: safda not valid
globalThis.window ??= window;
// @ts-expect-error: ajsdfj not valid
globalThis.navigator = {
  userAgent: 'node.js',
};

// @ts-expect-error: jaskldfjklasfdgjkl;asijo;
copyProps(window, globalThis);
