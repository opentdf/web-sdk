# DPoP CLI Flags Design — DSPX-3397 (web-sdk slice)

**Date:** 2026-06-09  
**Branch:** DSPX-3397-web-sdk  
**Scope:** `cli/src/cli.ts` only — no SDK core changes

---

## Background

The branch already ships `lib/src/auth/dpop-nonce.ts` (nonce cache) and `lib/src/auth/interceptors.ts` (`authTokenDPoPInterceptor` with 401-retry). The CLI already has `--dpop` as a boolean and wires `disableDPoP: !argv.dpop` into `OpenTDF`. However, it always falls back to RSA-2048 key generation (not ES256 as RFC 9449 §4.2 requires by default) and has no way to supply a custom PEM key.

---

## Flags

| Flag | Yargs config | Semantics |
|---|---|---|
| `--dpop[=alg]` | `type: 'string'`, group `Security:` | `--dpop` → enable with ES256 (empty string → default). `--dpop=ES512` → enable with specific alg. Omitted → DPoP disabled. |
| `--dpop-key <path>` | `type: 'string'`, alias `dpop-key`, group `Security:` | PEM-encoded private key file. Enables DPoP alone (algorithm inferred from key type). |

Supported algorithm values: `ES256`, `ES384`, `ES512`, `RS256`, `RS384`, `RS512`. RS384/RS512 are accepted but the SDK's `determineJWSAlgorithmFromKeyInfo` maps all RSA keys to RS256 — document in help.

Help text for both flags contains the word "dpop" so `grep -i dpop` matches.

---

## DPoP Enablement Logic

```ts
// Normalize the --dpop flag: '' (flag with no value) → 'ES256'
const dpopAlg = argv.dpop === undefined ? undefined : (argv.dpop || 'ES256');
const dpopEnabled = dpopAlg !== undefined || !!argv.dpopKey;
```

---

## Key Pair Resolution

A single async helper `resolveDPoPKeyPair(alg, keyPath)` in `cli.ts`:

### Auto-generated keys

- **EC (ES256/ES384/ES512):** `crypto.subtle.generateKey({ name: 'ECDSA', namedCurve }, true, ['sign','verify'])` → export PKCS8/SPKI PEM → `WebCryptoService.importPrivateKey/importPublicKey(pem, { usage: 'sign' })`
- **RSA (RS256/RS384/RS512):** `WebCryptoService.generateSigningKeyPair()` (existing, returns RSA-2048)

### PEM key from file (`--dpop-key`)

1. Read the file
2. Strip PEM armor, decode DER
3. Try `crypto.subtle.importKey('pkcs8', der, { name: 'ECDSA', namedCurve }, true, ['sign'])` for each curve (P-256, P-384, P-521), then RSA fallback
4. Export successful import as JWK; strip private components (`d`, `p`, `q`, `dp`, `dq`, `qi`); import public JWK; export as SPKI PEM
5. Import both keys through `WebCryptoService.importPrivateKey/importPublicKey(pem, { usage: 'sign' })` to get the opaque `KeyPair`

Algorithm of the loaded key is inferred automatically (the SDK's `importPrivateKey` reads the OID).

---

## OpenTDF Constructor Changes

Same pattern in both `encrypt` and `decrypt` handlers:

```ts
const dpopKeyPair = dpopEnabled
  ? await resolveDPoPKeyPair(dpopAlg, argv.dpopKey)
  : undefined;

const client = new OpenTDF({
  ...existingOptions,
  disableDPoP: !dpopEnabled,
  dpopKeys: dpopKeyPair ? Promise.resolve(dpopKeyPair) : undefined,
});
```

The existing interceptor in the SDK then uses these keys for every request, including the 401-nonce retry flow.

---

## Type Change: `--dpop` boolean → string

`argv.dpop` changes from `boolean | undefined` to `string | undefined`. Two places in the decrypt handler need updating:

```ts
// Before
console.assert(accessToken.cnf?.jkt, 'Access token must have a cnf.jkt');  // guarded by if (argv.dpop)
console.assert(!argv.dpop || dpopToken, 'DPoP requested but absent');

// After (use dpopEnabled instead of argv.dpop)
console.assert(accessToken.cnf?.jkt, 'Access token must have a cnf.jkt');  // guarded by if (dpopEnabled)
console.assert(!dpopEnabled || dpopToken, 'DPoP requested but absent');
```

---

## Validation

- Unknown algorithm string → `CLIError` before key generation
- PEM file not found / unparseable → `CLIError` with path in message
- `--dpop-key` with a valid PEM overrides the algorithm from `--dpop` (key type wins)

---

## Verification Steps

1. `npm run build` from `cli/` — must succeed
2. `npm test` — existing logger tests must pass
3. `npx @opentdf/ctl encrypt --help | grep -i dpop` — must show both `--dpop` and `--dpop-key`
4. `node dist/src/cli.js supports dpop; echo $?` — must print `0`

---

## Files Changed

- `cli/src/cli.ts` — only file touched
