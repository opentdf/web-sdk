import type { validateTdf } from '../src/validation.js';

// Compiled by the test tsconfig; never called at runtime. Lax-schema success
// must not make fields required by the full Manifest type safe to dereference.
export function checkLaxManifestType(manifest: Awaited<ReturnType<typeof validateTdf>>): void {
  // @ts-expect-error The lax schema permits absent assertions.
  const assertions: readonly unknown[] = manifest.assertions;
  void assertions;
  // @ts-expect-error The lax schema permits empty encryptionInformation.
  const encryption: { keyAccess: readonly unknown[] } = manifest.encryptionInformation;
  void encryption;
}
