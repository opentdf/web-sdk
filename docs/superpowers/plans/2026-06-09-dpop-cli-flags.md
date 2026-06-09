# DPoP CLI Flags Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `--dpop[=alg]` and `--dpop-key <path>` flags to the `@opentdf/ctl` CLI so callers can enable DPoP with ES256 (default) or a specific algorithm, using an auto-generated or PEM-supplied key.

**Architecture:** One new file (`cli/src/dpop-helpers.ts`) holds all key-management logic; `cli/src/cli.ts` changes only its option definitions and call sites. The helpers generate ECDSA keys via WebCrypto directly, then wrap them through the SDK's `importPrivateKey`/`importPublicKey` to get the opaque `KeyPair` type `OpenTDF` needs.

**Tech Stack:** TypeScript 5, yargs 18, Node 24 WebCrypto (`crypto.subtle`), `@opentdf/sdk` (singlecontainer subpath provides `WebCryptoService` and `KeyPair`)

---

## File Map

| Path | Action | Responsibility |
|---|---|---|
| `cli/src/dpop-helpers.ts` | **Create** | DPoP key-pair generation, PEM loading, algorithm resolution |
| `cli/tests/dpop-helpers.spec.ts` | **Create** | Unit tests for the helpers |
| `cli/src/cli.ts` | **Modify** | Option definitions, enablement logic, wiring into encrypt/decrypt |

---

### Task 1: Write failing tests

**Files:**
- Create: `cli/tests/dpop-helpers.spec.ts`

- [ ] **Step 1.1: Create the test file**

```typescript
// cli/tests/dpop-helpers.spec.ts
import { expect } from '@esm-bundle/chai';
import {
  derToPem,
  generateEphemeralDPoPKeyPair,
  resolveDPoPKeyPair,
} from '../src/dpop-helpers.js';

describe('derToPem', function () {
  it('wraps DER bytes in PEM armor with the given type', function () {
    const der = new Uint8Array([0x01, 0x02, 0x03]);
    const pem = derToPem(der, 'PUBLIC KEY');
    expect(pem).to.include('-----BEGIN PUBLIC KEY-----');
    expect(pem).to.include('-----END PUBLIC KEY-----');
    expect(pem).to.include('AQID'); // base64 of [1,2,3]
  });

  it('wraps an ArrayBuffer in PEM armor', function () {
    const der = new Uint8Array([0x01, 0x02]).buffer;
    const pem = derToPem(der, 'PRIVATE KEY');
    expect(pem).to.include('-----BEGIN PRIVATE KEY-----');
    expect(pem).to.include('-----END PRIVATE KEY-----');
  });
});

describe('generateEphemeralDPoPKeyPair', function () {
  it('generates ES256 (ec:secp256r1) key pair', async function () {
    const kp = await generateEphemeralDPoPKeyPair('ES256');
    expect(kp.publicKey.algorithm).to.equal('ec:secp256r1');
  });

  it('generates ES384 (ec:secp384r1) key pair', async function () {
    const kp = await generateEphemeralDPoPKeyPair('ES384');
    expect(kp.publicKey.algorithm).to.equal('ec:secp384r1');
  });

  it('generates ES512 (ec:secp521r1) key pair', async function () {
    const kp = await generateEphemeralDPoPKeyPair('ES512');
    expect(kp.publicKey.algorithm).to.equal('ec:secp521r1');
  });

  it('generates RS256 (rsa:2048) key pair', async function () {
    this.timeout(15_000);
    const kp = await generateEphemeralDPoPKeyPair('RS256');
    expect(kp.publicKey.algorithm).to.equal('rsa:2048');
  });

  it('throws on unknown algorithm', async function () {
    try {
      await generateEphemeralDPoPKeyPair('HS256');
      expect.fail('should have thrown');
    } catch (err) {
      expect((err as Error).message).to.include('Unsupported DPoP algorithm');
    }
  });
});

describe('resolveDPoPKeyPair', function () {
  it('returns undefined when both alg and keyPath are undefined', async function () {
    const result = await resolveDPoPKeyPair(undefined, undefined);
    expect(result).to.be.undefined;
  });

  it('returns an ES256 key pair when alg is ES256', async function () {
    const result = await resolveDPoPKeyPair('ES256', undefined);
    expect(result).to.not.be.undefined;
    expect(result!.publicKey.algorithm).to.equal('ec:secp256r1');
  });
});
```

- [ ] **Step 1.2: Verify tests fail (module not found)**

```bash
cd cli && npm run build 2>&1 | tail -5
```

Expected: TypeScript error — `Cannot find module '../src/dpop-helpers.js'`

---

### Task 2: Implement `cli/src/dpop-helpers.ts`

**Files:**
- Create: `cli/src/dpop-helpers.ts`

- [ ] **Step 2.1: Create the implementation file**

```typescript
// cli/src/dpop-helpers.ts
import { readFile } from 'node:fs/promises';
import { type KeyPair, WebCryptoService } from '@opentdf/sdk/singlecontainer';
import { CLIError } from './logger.js';

const VALID_DPOP_ALGS = ['ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512'] as const;
export type DPoPAlg = (typeof VALID_DPOP_ALGS)[number];

const EC_CURVE_MAP: Record<string, string> = {
  ES256: 'P-256',
  ES384: 'P-384',
  ES512: 'P-521',
};

/** Convert a DER buffer to a PEM string with the given type label. */
export function derToPem(der: Uint8Array | ArrayBuffer, type: string): string {
  const bytes = der instanceof ArrayBuffer ? new Uint8Array(der) : der;
  const b64 = btoa(String.fromCharCode(...bytes));
  const lines = b64.match(/.{1,64}/g)!.join('\n');
  return `-----BEGIN ${type}-----\n${lines}\n-----END ${type}-----`;
}

/**
 * Generate an ephemeral DPoP key pair for the given JWS algorithm.
 * ES256/ES384/ES512 → ECDSA key via WebCrypto + SDK import.
 * RS256/RS384/RS512 → RSA-2048 via SDK's generateSigningKeyPair() (all map to RS256 in DPoP proof).
 */
export async function generateEphemeralDPoPKeyPair(alg: string): Promise<KeyPair> {
  if (!VALID_DPOP_ALGS.includes(alg as DPoPAlg)) {
    throw new CLIError(
      'CRITICAL',
      `Unsupported DPoP algorithm: ${alg}. Valid values: ${VALID_DPOP_ALGS.join(', ')}`
    );
  }

  const namedCurve = EC_CURVE_MAP[alg];
  if (namedCurve) {
    const raw = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve }, true, [
      'sign',
      'verify',
    ]);
    const [privDer, pubDer] = await Promise.all([
      crypto.subtle.exportKey('pkcs8', raw.privateKey),
      crypto.subtle.exportKey('spki', raw.publicKey),
    ]);
    const privPem = derToPem(privDer, 'PRIVATE KEY');
    const pubPem = derToPem(pubDer, 'PUBLIC KEY');
    const [privateKey, publicKey] = await Promise.all([
      WebCryptoService.importPrivateKey!(privPem, { usage: 'sign', extractable: true }),
      WebCryptoService.importPublicKey(pubPem, { usage: 'sign', extractable: true }),
    ]);
    return { publicKey, privateKey };
  }

  // RSA fallback — generateSigningKeyPair() produces RSA-2048 (DPoP maps this to RS256)
  return WebCryptoService.generateSigningKeyPair();
}

/**
 * Load a DPoP key pair from a PKCS8 PEM-encoded private key file.
 * Derives the public key from the private key via JWK round-trip.
 * Supports ECDSA (P-256, P-384, P-521) and RSA (PKCS1-v1_5 SHA-256).
 */
export async function loadDPoPKeyPairFromPem(pemPath: string): Promise<KeyPair> {
  let privatePem: string;
  try {
    privatePem = await readFile(pemPath, 'utf8');
  } catch (err) {
    throw new CLIError('CRITICAL', `Cannot read DPoP key file: ${pemPath}`, err as Error);
  }

  const b64 = privatePem.replace(/-----[\w\s]+-----|[\r\n]/g, '');
  const der = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

  // Try EC curves (P-256, P-384, P-521)
  for (const namedCurve of ['P-256', 'P-384', 'P-521']) {
    try {
      const privCK = await crypto.subtle.importKey(
        'pkcs8',
        der,
        { name: 'ECDSA', namedCurve },
        true,
        ['sign']
      );
      return await buildKeyPairFromCryptoKey(privatePem, privCK, { name: 'ECDSA', namedCurve });
    } catch {
      // wrong curve or not an EC key — try next
    }
  }

  // Try RSA (PKCS1-v1_5 SHA-256)
  try {
    const privCK = await crypto.subtle.importKey(
      'pkcs8',
      der,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      true,
      ['sign']
    );
    return await buildKeyPairFromCryptoKey(privatePem, privCK, {
      name: 'RSASSA-PKCS1-v1_5',
      hash: 'SHA-256',
    });
  } catch {
    // not RSA either
  }

  throw new CLIError(
    'CRITICAL',
    `Cannot parse DPoP key from ${pemPath}: expected PKCS8 PEM with ECDSA (P-256/P-384/P-521) or RSA private key`
  );
}

/**
 * Derive the public key from an already-imported private CryptoKey via JWK round-trip,
 * then import both through the SDK to get the opaque KeyPair type.
 */
async function buildKeyPairFromCryptoKey(
  privatePem: string,
  privCK: CryptoKey,
  algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams
): Promise<KeyPair> {
  // Export private key as JWK; strip private components to build the public JWK
  const privJwk = await crypto.subtle.exportKey('jwk', privCK);
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { d, p, q, dp, dq, qi, ...pubJwkProps } = privJwk;
  const pubJwk: JsonWebKey = { ...pubJwkProps, key_ops: ['verify'] };

  const pubCK = await crypto.subtle.importKey('jwk', pubJwk, algorithm, true, ['verify']);
  const pubDer = await crypto.subtle.exportKey('spki', pubCK);
  const pubPem = derToPem(pubDer, 'PUBLIC KEY');

  const [privateKey, publicKey] = await Promise.all([
    WebCryptoService.importPrivateKey!(privatePem, { usage: 'sign', extractable: true }),
    WebCryptoService.importPublicKey(pubPem, { usage: 'sign', extractable: true }),
  ]);
  return { publicKey, privateKey };
}

/**
 * Main entry point: resolve a DPoP KeyPair from CLI arguments.
 * Returns undefined if DPoP is not requested.
 */
export async function resolveDPoPKeyPair(
  alg: string | undefined,
  keyPath: string | undefined
): Promise<KeyPair | undefined> {
  if (keyPath) {
    return loadDPoPKeyPairFromPem(keyPath);
  }
  if (alg) {
    return generateEphemeralDPoPKeyPair(alg);
  }
  return undefined;
}
```

- [ ] **Step 2.2: Run tests to verify they pass**

```bash
cd cli && npm test 2>&1 | tail -20
```

Expected: All `dpop-helpers` tests pass. The logger tests also still pass.

- [ ] **Step 2.3: Commit**

```bash
cd cli && git add src/dpop-helpers.ts tests/dpop-helpers.spec.ts && git commit -m "feat(cli): add DPoP key pair helpers (DSPX-3397)"
```

---

### Task 3: Update CLI option definitions in `cli.ts`

**Files:**
- Modify: `cli/src/cli.ts`

- [ ] **Step 3.1: Add import for dpop helpers and `readFile`**

At the top of `cli/src/cli.ts`, change:

```typescript
// Before:
import { type KeyPair } from '@opentdf/sdk/singlecontainer';

// After:
import { type KeyPair } from '@opentdf/sdk/singlecontainer';
import { resolveDPoPKeyPair } from './dpop-helpers.js';
```

- [ ] **Step 3.2: Replace the `--dpop` boolean option with a string option, add `--dpop-key`**

Find this block (around line 320 in the global options):

```typescript
      .option('dpop', {
        group: 'Security:',
        desc: 'Use DPoP for token binding',
        type: 'boolean',
      })
```

Replace with:

```typescript
      .option('dpop', {
        group: 'Security:',
        desc: 'Enable DPoP token binding. Optional value selects algorithm: ES256 (default), ES384, ES512, RS256. Use --dpop=ES512 to specify.',
        type: 'string',
      })
      .option('dpopKey', {
        alias: 'dpop-key',
        group: 'Security:',
        desc: 'Path to PEM-encoded PKCS8 private key for DPoP signing. Enables DPoP alone if --dpop is omitted.',
        type: 'string',
      })
```

- [ ] **Step 3.3: Build to verify no type errors**

```bash
cd cli && npm run build 2>&1 | grep -E "error|Error" | head -20
```

Expected: No errors. (TypeScript will now treat `argv.dpop` as `string | undefined` instead of `boolean | undefined` — we'll fix the call sites in the next tasks.)

---

### Task 4: Wire DPoP into the `encrypt` command

**Files:**
- Modify: `cli/src/cli.ts` — the `encrypt` command handler

- [ ] **Step 4.1: Add DPoP enablement logic and key resolution before creating `OpenTDF`**

Find the `encrypt` command handler (around line 600). It currently starts like:

```typescript
        async (argv) => {
          log('DEBUG', 'Running encrypt command');
          const authProvider = await processAuth(argv);
          log('DEBUG', `Initialized auth provider ${JSON.stringify(authProvider)}`);
          const guessedPolicyEndpoint = guessPolicyUrl(argv);

          const client = new OpenTDF({
            authProvider,
            defaultCreateOptions: {
              defaultKASEndpoint: argv.kasEndpoint,
            },
            disableDPoP: !argv.dpop,
            policyEndpoint: guessedPolicyEndpoint,
            platformUrl: argv.platformUrl || guessedPolicyEndpoint,
          });
```

Replace with:

```typescript
        async (argv) => {
          log('DEBUG', 'Running encrypt command');
          const authProvider = await processAuth(argv);
          log('DEBUG', `Initialized auth provider ${JSON.stringify(authProvider)}`);
          const guessedPolicyEndpoint = guessPolicyUrl(argv);

          const dpopAlg = argv.dpop === undefined ? undefined : (argv.dpop || 'ES256');
          const dpopEnabled = dpopAlg !== undefined || !!argv.dpopKey;
          const dpopKeyPair = await resolveDPoPKeyPair(dpopAlg, argv.dpopKey);

          const client = new OpenTDF({
            authProvider,
            defaultCreateOptions: {
              defaultKASEndpoint: argv.kasEndpoint,
            },
            disableDPoP: !dpopEnabled,
            dpopKeys: dpopKeyPair ? Promise.resolve(dpopKeyPair) : undefined,
            policyEndpoint: guessedPolicyEndpoint,
            platformUrl: argv.platformUrl || guessedPolicyEndpoint,
          });
```

- [ ] **Step 4.2: Build to verify**

```bash
cd cli && npm run build 2>&1 | grep -E "error|Error" | head -20
```

Expected: No errors.

---

### Task 5: Wire DPoP into the `decrypt` command

**Files:**
- Modify: `cli/src/cli.ts` — the `decrypt` command handler

- [ ] **Step 5.1: Add DPoP enablement logic and fix DPoP assertions**

Find the `decrypt` command handler. It currently starts with:

```typescript
        async (argv) => {
          log('DEBUG', 'Running decrypt command');
          const allowedKases = argv.allowList?.split(',');
          log('DEBUG', `Allowed KASes: ${allowedKases}`);
          const ignoreAllowList = !!argv.ignoreAllowList;
          if (!argv.oidcEndpoint) {
            throw new CLIError('CRITICAL', 'oidcEndpoint must be specified');
          }
          const authProvider = await processAuth(argv);
          log('DEBUG', `Initialized auth provider ${JSON.stringify(authProvider)}`);
          const guessedPolicyEndpoint = guessPolicyUrl(argv);
          const client = new OpenTDF({
            authProvider,
            defaultCreateOptions: {
              defaultKASEndpoint: argv.kasEndpoint,
            },
            defaultReadOptions: {
              allowedKASEndpoints: allowedKases,
              ignoreAllowlist: ignoreAllowList,
              noVerify: !!argv.noVerifyAssertions,
            },
            disableDPoP: !argv.dpop,
            policyEndpoint: guessedPolicyEndpoint,
            platformUrl: argv.platformUrl || guessedPolicyEndpoint,
          });
```

Replace with:

```typescript
        async (argv) => {
          log('DEBUG', 'Running decrypt command');
          const allowedKases = argv.allowList?.split(',');
          log('DEBUG', `Allowed KASes: ${allowedKases}`);
          const ignoreAllowList = !!argv.ignoreAllowList;
          if (!argv.oidcEndpoint) {
            throw new CLIError('CRITICAL', 'oidcEndpoint must be specified');
          }
          const authProvider = await processAuth(argv);
          log('DEBUG', `Initialized auth provider ${JSON.stringify(authProvider)}`);
          const guessedPolicyEndpoint = guessPolicyUrl(argv);

          const dpopAlg = argv.dpop === undefined ? undefined : (argv.dpop || 'ES256');
          const dpopEnabled = dpopAlg !== undefined || !!argv.dpopKey;
          const dpopKeyPair = await resolveDPoPKeyPair(dpopAlg, argv.dpopKey);

          const client = new OpenTDF({
            authProvider,
            defaultCreateOptions: {
              defaultKASEndpoint: argv.kasEndpoint,
            },
            defaultReadOptions: {
              allowedKASEndpoints: allowedKases,
              ignoreAllowlist: ignoreAllowList,
              noVerify: !!argv.noVerifyAssertions,
            },
            disableDPoP: !dpopEnabled,
            dpopKeys: dpopKeyPair ? Promise.resolve(dpopKeyPair) : undefined,
            policyEndpoint: guessedPolicyEndpoint,
            platformUrl: argv.platformUrl || guessedPolicyEndpoint,
          });
```

- [ ] **Step 5.2: Fix DPoP token assertions in the decrypt command**

In the same `decrypt` handler, find the two DPoP assertion lines (inside the `for` loop over headers and after it). Change both from `argv.dpop` to `dpopEnabled`:

```typescript
              // Before:
              if (argv.dpop) {
                console.assert(accessToken.cnf?.jkt, 'Access token must have a cnf.jkt');
              }

              // After:
              if (dpopEnabled) {
                console.assert(accessToken.cnf?.jkt, 'Access token must have a cnf.jkt');
              }
```

```typescript
            // Before:
            console.assert(!argv.dpop || dpopToken, 'DPoP requested but absent');

            // After:
            console.assert(!dpopEnabled || dpopToken, 'DPoP requested but absent');
```

- [ ] **Step 5.3: Build to verify no remaining type errors**

```bash
cd cli && npm run build 2>&1 | grep -E "error|Error" | head -20
```

Expected: No errors.

- [ ] **Step 5.4: Run all tests**

```bash
cd cli && npm test 2>&1 | tail -20
```

Expected: All tests pass (logger + dpop-helpers).

- [ ] **Step 5.5: Commit**

```bash
git add cli/src/cli.ts && git commit -m "feat(cli): add --dpop[=alg] and --dpop-key flags for DPoP support (DSPX-3397)"
```

---

### Task 6: Smoke test and final push

**Files:** none changed

- [ ] **Step 6.1: Verify help output contains dpop**

```bash
cd cli && node dist/src/cli.js encrypt --help | grep -i dpop
```

Expected output (both lines must appear):
```
  --dpop      Enable DPoP token binding. Optional value selects algorithm...
  --dpop-key  Path to PEM-encoded PKCS8 private key for DPoP signing...
```

- [ ] **Step 6.2: Verify `supports dpop` exits 0**

```bash
cd cli && node dist/src/cli.js supports dpop; echo "exit: $?"
```

Expected: `exit: 0`

- [ ] **Step 6.3: Verify `--dpop` parses without error**

```bash
cd cli && node dist/src/cli.js encrypt --dpop --help 2>&1 | grep -i dpop
```

Expected: no parse errors, dpop flags appear in help.

- [ ] **Step 6.4: Push to remote**

```bash
git push origin DSPX-3397-web-sdk
```

Expected: Push succeeds. Pre-commit hooks (prettier, eslint) run during the earlier commits — if they fail, run `npm run format && npm run lint` in `cli/` and re-commit.

---

## Self-Review

**Spec coverage:**
- `--dpop` (no value → ES256) ✓ Task 3 + `dpopAlg = argv.dpop || 'ES256'`
- `--dpop=<alg>` (specific algorithm) ✓ Task 3, yargs string type captures `=value`
- `--dpop-key <path>` (PEM key) ✓ Task 3, Task 2 `loadDPoPKeyPairFromPem`
- `--dpop-key` alone enables DPoP ✓ `dpopEnabled = dpopAlg !== undefined || !!argv.dpopKey`
- Help text mentions "dpop" ✓ both option descriptions contain the word
- Wire into existing interceptor ✓ `dpopKeys` passed to `OpenTDF` which feeds the existing `authTokenDPoPInterceptor`
- Don't reimplement nonce-retry ✓ interceptor unchanged
- No new auth client ✓
- `npm run build` + `npm test` verification ✓ Task 2 and Task 6
- Smoke `grep -i dpop` ✓ Task 6 step 1
- `feat(cli):` commit convention ✓ Task 5 step 5 commit message

**Placeholder scan:** None found.

**Type consistency:**
- `resolveDPoPKeyPair(alg, keyPath)` — defined in Task 2, used identically in Tasks 4 and 5 ✓
- `dpopAlg`, `dpopEnabled`, `dpopKeyPair` — defined and used within the same handler in each task ✓
- `WebCryptoService.importPrivateKey!` — non-null assertion consistent in both usages within `dpop-helpers.ts` ✓
