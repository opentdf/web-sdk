import type { isValidTdf } from '../src/validation.js';

// Compiled by the test tsconfig; the predicate returns a boolean, not a manifest.
export function checkValidationType(result: Awaited<ReturnType<typeof isValidTdf>>): boolean {
  return result;
}
