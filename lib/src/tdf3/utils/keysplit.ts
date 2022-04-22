import { randomBytes } from 'crypto';

export function bxor(b1: Uint8Array, b2: Uint8Array): Uint8Array {
  const result = Buffer.alloc(b1.length);
  for (let i = 0; i <= b1.length; i++) {
    result[i] = b1[i] ^ b2[i];
  }
  return result;
}

/**
 * Spreads the data in `key` across `n` shares of the same size, using
 * secure random noise so that any n-1 subset of the keys contains no
 * information. This allows a user to store a key across multiple KAS servers.
 * @param key The data to split
 * @param n The number of entries to split across
 * @returns `n` entries of `length(key)` size
 */
export function keySplit(key: Uint8Array, n = 1) {
  if (!(key instanceof Uint8Array)) {
    throw Error('ERROR in keySplit - key is not an unsigned byte array');
  }
  if (n <= 0) {
    throw Error('ERROR in keySplit - n is not a positive integer');
  }
  const keyLength = key.length;
  const splits = [];
  let currKey = key;
  // https://en.wikipedia.org/wiki/Secret_sharing#t_=_n
  for (let i = 1; i < n; i++) {
    const shareI = randomBytes(keyLength);
    currKey = bxor(shareI, currKey);
    splits.push(shareI);
  }
  splits.push(currKey);
  return splits;
}

/**
 * Combines K secret shares, as generated from `keySplit`, into a single value.
 * Note this does no verfication!
 * @param splits the split values, aggregated from KASen
 * @returns the merged value.
 */
export function keyMerge(splits: Uint8Array[]): Uint8Array {
  if (!Array.isArray(splits)) throw Error('ERROR in keyMerge - splits is not an array');
  if (splits.length < 1) throw Error('ERROR in keyMerge - splits must have at least one element');

  let currKey = splits[0];
  for (let i = 1; i < splits.length; i++) {
    currKey = bxor(currKey, splits[i]);
  }
  return currKey;
}
