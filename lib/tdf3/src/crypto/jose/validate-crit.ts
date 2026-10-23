import { JWS_RECOGNIZED, validateCrit } from './vendor/index.js';

const joseValidateCrit = validateCrit as (
  Err: new (message?: string, options?: { cause?: unknown }) => Error,
  recognizedDefault: typeof JWS_RECOGNIZED,
  recognizedOption: Record<string, boolean> | undefined,
  protectedHeader: Record<string, unknown> | undefined,
  joseHeader: Record<string, unknown>
) => Iterable<string>;

// Validates "crit" against jose's JWS defaults ("b64") plus `recognizedOption`.
// The defaults stay jose's own: its validateCrit expects a Map on some versions
// and a null-prototype object on others.
export default function validateJwsCrit(
  Err: new (message?: string, options?: { cause?: unknown }) => Error,
  recognizedOption: Record<string, boolean> | undefined,
  protectedHeader: Record<string, unknown> | undefined,
  joseHeader: Record<string, unknown>
): Set<string> {
  return new Set(
    joseValidateCrit(Err, JWS_RECOGNIZED, recognizedOption, protectedHeader, joseHeader)
  );
}
