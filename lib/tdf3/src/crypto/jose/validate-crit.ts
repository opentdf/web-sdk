import validateCrit from './vendor/lib/validate_crit.js';

export default validateCrit as (
  Err: new (message?: string, options?: { cause?: unknown }) => Error,
  recognizedDefault: Map<string, boolean>,
  recognizedOption: Record<string, boolean> | undefined,
  protectedHeader: Record<string, unknown> | undefined,
  joseHeader: Record<string, unknown>
) => Set<string>;
