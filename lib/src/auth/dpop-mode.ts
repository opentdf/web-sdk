/** The form of `htu` used for DPoP proofs on resource requests. */
export type DPoPMode = 'auto' | 'legacy' | 'rfc9449';
type ResolvedMode = Exclude<DPoPMode, 'auto'>;

const WELL_KNOWN_PROCEDURE = '/wellknownconfiguration.WellKnownService/GetWellKnownConfiguration';
const PROTECTED_RESOURCE_PATH = '/.well-known/oauth-protected-resource';
const DEFAULT_CACHE_TTL_MS = 5 * 60 * 1000;
const DEFAULT_RETRY_MS = 30 * 1000;
const DEFAULT_TIMEOUT_MS = 10 * 1000;
const MAX_DOCUMENT_BYTES = 1 << 20;

type DiscoveryAnswer =
  | { kind: 'document'; value: Record<string, unknown> }
  | { kind: 'missing' }
  | { kind: 'inconclusive' };
type CachedMode = { mode: ResolvedMode; expiresAt: number };

function abortError(signal: AbortSignal): Error {
  return signal.reason instanceof Error ? signal.reason : new DOMException('Aborted', 'AbortError');
}

export type DPoPModeResolverOptions = {
  /** `auto` discovers per origin. Fixed modes make no discovery requests. */
  mode?: DPoPMode;
  /** Fetch used only for unauthenticated discovery. */
  fetch?: typeof globalThis.fetch;
  /** How long a conclusive answer is reused. */
  cacheTtlMs?: number;
  /** How long an inconclusive legacy fallback is reused. */
  retryIntervalMs?: number;
  /** Total time allowed for both discovery requests. */
  timeoutMs?: number;
  /** Clock injection for deterministic cache tests. */
  now?: () => number;
};

/** The RFC 9449 URI form, without query or fragment. */
export function fullDPoPHTU(requestUrl: string): string {
  const url = new URL(requestUrl);
  return `${url.origin}${url.pathname}`;
}

/**
 * Older Connect KAS implementations compare `htu` with the bare RPC procedure:
 * the last two path segments (`/package.Service/Method`), so any proxy prefix is
 * dropped. URLs with fewer than two segments fall back to {@link fullDPoPHTU}.
 */
export function legacyRpcDPoPHTU(requestUrl: string): string {
  const url = new URL(requestUrl);
  const segments = url.pathname.split('/').filter(Boolean);
  return segments.length >= 2 ? `/${segments.slice(-2).join('/')}` : fullDPoPHTU(requestUrl);
}

/** Whether the OpenTDF well-known configuration advertises full-URI DPoP proofs. */
export function advertisesRFC9449(configuration: unknown): boolean {
  if (!configuration || typeof configuration !== 'object' || Array.isArray(configuration)) {
    return false;
  }
  const values = configuration as Record<string, unknown>;
  const block = values.dpop;
  if (block && typeof block === 'object' && !Array.isArray(block)) {
    const supported = (block as Record<string, unknown>).rfc9449;
    if (typeof supported === 'boolean') return supported;
  }
  return (
    Array.isArray(values.dpop_signing_alg_values_supported) &&
    values.dpop_signing_alg_values_supported.length > 0
  );
}

function hasAlgorithms(document: Record<string, unknown>): boolean {
  return (
    Array.isArray(document.dpop_signing_alg_values_supported) &&
    document.dpop_signing_alg_values_supported.length > 0
  );
}

async function readDiscoveryJSON(
  fetcher: typeof globalThis.fetch,
  url: string,
  method: 'GET' | 'POST',
  signal: AbortSignal
): Promise<DiscoveryAnswer> {
  try {
    const response = await fetcher(url, {
      method,
      headers:
        method === 'POST'
          ? {
              Accept: 'application/json',
              'Content-Type': 'application/json',
              'Connect-Protocol-Version': '1',
            }
          : { Accept: 'application/json' },
      ...(method === 'POST' ? { body: '{}' } : {}),
      credentials: 'omit',
      redirect: 'manual',
      signal,
    });
    if ([404, 405, 501].includes(response.status)) return { kind: 'missing' };
    if (response.status !== 200) return { kind: 'inconclusive' };
    const reader = response.body?.getReader();
    if (!reader) return { kind: 'inconclusive' };
    const chunks: Uint8Array[] = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_DOCUMENT_BYTES) {
        await reader.cancel();
        return { kind: 'inconclusive' };
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    if (!size) return { kind: 'inconclusive' };
    const value: unknown = JSON.parse(new TextDecoder().decode(bytes));
    if (!value || typeof value !== 'object' || Array.isArray(value)) return { kind: 'missing' };
    return { kind: 'document', value: value as Record<string, unknown> };
  } catch (error) {
    // A malformed 200 is a definitive absence of the expected document. A
    // network/stream error or timeout is inconclusive and is retried soon.
    if (error instanceof SyntaxError) return { kind: 'missing' };
    return { kind: 'inconclusive' };
  }
}

/**
 * Discovers the DPoP proof style independently for each server origin.
 * Discovery never sends Authorization, DPoP, or cookies. Concurrent requests to
 * the same origin share one discovery.
 *
 * In `auto` mode, an origin is `rfc9449` only if it advertises support; anything
 * else, including failed or blocked discovery, is `legacy`. This keeps older
 * platforms working without configuration, at the cost of proofs that do not
 * name the origin. Use the `rfc9449` mode where every server supports it.
 * Failed discovery is cached only for `retryIntervalMs`, so a transient failure
 * does not pin a server to legacy for the full `cacheTtlMs`.
 */
export class DPoPModeResolver {
  readonly mode: DPoPMode;
  private readonly fetcher: typeof globalThis.fetch;
  private readonly now: () => number;
  private readonly cacheTtlMs: number;
  private readonly retryIntervalMs: number;
  private readonly timeoutMs: number;
  private readonly cache = new Map<string, CachedMode>();
  private readonly inFlight = new Map<string, Promise<ResolvedMode>>();

  constructor(options: DPoPModeResolverOptions = {}) {
    this.mode = options.mode ?? 'auto';
    this.fetcher = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
    this.now = options.now ?? Date.now;
    this.cacheTtlMs = options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
    this.retryIntervalMs = options.retryIntervalMs ?? DEFAULT_RETRY_MS;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  /** Resolve once per origin, with a five-minute conclusive cache by default. */
  async modeFor(requestUrl: string, signal?: AbortSignal): Promise<ResolvedMode> {
    if (this.mode !== 'auto') return this.mode;
    const origin = new URL(requestUrl).origin;
    const known = this.cache.get(origin);
    if (known && this.now() < known.expiresAt) return known.mode;

    let pending = this.inFlight.get(origin);
    if (!pending) {
      pending = this.discover(origin);
      this.inFlight.set(origin, pending);
      void pending.then(
        () => this.inFlight.delete(origin),
        () => this.inFlight.delete(origin)
      );
    }
    if (!signal) return pending;
    if (signal.aborted) throw abortError(signal);
    return new Promise<ResolvedMode>((resolve, reject) => {
      const onAbort = () => reject(abortError(signal));
      signal.addEventListener('abort', onAbort, { once: true });
      void pending.then(resolve, reject).then(() => signal.removeEventListener('abort', onAbort));
    });
  }

  /** Select `htu` for a Connect RPC. Not used for token-endpoint or other non-RPC proofs. */
  async htuForRpc(requestUrl: string, signal?: AbortSignal): Promise<string> {
    const mode = await this.modeFor(requestUrl, signal);
    return mode === 'legacy' ? legacyRpcDPoPHTU(requestUrl) : fullDPoPHTU(requestUrl);
  }

  private async discover(origin: string): Promise<ResolvedMode> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    let mode: ResolvedMode = 'legacy';
    let conclusive: boolean;
    try {
      const wellKnown = await readDiscoveryJSON(
        this.fetcher,
        origin + WELL_KNOWN_PROCEDURE,
        'POST',
        controller.signal
      );
      if (wellKnown.kind === 'document' && advertisesRFC9449(wellKnown.value.configuration)) {
        mode = 'rfc9449';
        conclusive = true;
      } else {
        const resource = await readDiscoveryJSON(
          this.fetcher,
          origin + PROTECTED_RESOURCE_PATH,
          'GET',
          controller.signal
        );
        if (resource.kind === 'document' && hasAlgorithms(resource.value)) {
          mode = 'rfc9449';
          conclusive = true;
        } else {
          conclusive = wellKnown.kind !== 'inconclusive' && resource.kind !== 'inconclusive';
        }
      }
    } finally {
      clearTimeout(timeout);
    }
    const lifetime = conclusive ? this.cacheTtlMs : Math.min(this.cacheTtlMs, this.retryIntervalMs);
    if (lifetime > 0) this.cache.set(origin, { mode, expiresAt: this.now() + lifetime });
    return mode;
  }
}
