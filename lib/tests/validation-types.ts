import type { isValidTdf, validateTdf } from '../src/validation.js';

// Type checks only, compiled by the test tsconfig and never run.

// isValidTdf resolves to a plain boolean.
export function checkValidationType(result: Awaited<ReturnType<typeof isValidTdf>>): boolean {
  return result;
}

// validateTdf's result narrows on `valid`: only a failure carries a reason.
export function checkValidationResultType(
  result: Awaited<ReturnType<typeof validateTdf>>
): string | undefined {
  return result.valid ? undefined : result.reason;
}
