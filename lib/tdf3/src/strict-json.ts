/**
 * Strict JSON reading and canonical serialization for manifests and assertions
 * (ZTDF assertions contract, Sections 3 and 4).
 *
 * `JSON.parse` silently keeps the last of duplicate member names, accepts lone
 * surrogates, and turns `1e400` into `Infinity`. Assertions are hashed as
 * received, so every reader must see the same object. {@link scanStrictJson}
 * runs over the raw text before `JSON.parse` builds a tree, and reports:
 *
 * - duplicate member names in any object, compared after decoding escapes
 *   (`duplicate-member`);
 * - at every level the SDKs model (manifest root, payload, encryption
 *   information, key access objects, integrity information, segments,
 *   assertions, statements, and bindings), a case variant of a modelled
 *   member name, or two member names that are case variants of each other
 *   (`ambiguous-member`); and
 * - inside assertion objects, surrogate code points or Unicode noncharacters in
 *   member names or strings, and numbers outside the IEEE 754 double range
 *   (`invalid-json`).
 *
 * The scanner uses only standard ECMAScript, so it runs in browsers and Node.
 */
import { type AssertionFailureReason } from '../../src/errors.js';

/**
 * Where a JSON container sits in the manifest model. Object levels have
 * modelled member names; array levels say what their elements are.
 */
type ObjectLevel =
  | 'manifest'
  | 'payload'
  | 'encryptionInformation'
  | 'keyAccessObject'
  | 'policyBinding'
  | 'method'
  | 'integrityInformation'
  | 'rootSignature'
  | 'segment'
  | 'assertion'
  | 'statement'
  | 'binding';
type ArrayLevel = 'keyAccess' | 'segments' | 'assertions';
type Level = ObjectLevel | ArrayLevel | 'other';

/**
 * The kind of document being scanned: a whole manifest, one assertion wire
 * object, or any other JSON, which is checked for syntax and duplicate member
 * names only.
 */
export type StrictJsonRoot = 'manifest' | 'assertion' | 'json';

/** The member names the SDKs model at each object level (spec Section 3.2). */
const MODELLED: Record<ObjectLevel, { path: string; names: readonly string[] }> = {
  manifest: {
    path: '',
    names: ['assertions', 'encryptionInformation', 'payload', 'schemaVersion', 'tdf_spec_version'],
  },
  payload: {
    path: 'payload',
    names: ['type', 'url', 'protocol', 'mimeType', 'isEncrypted', 'tdf_spec_version'],
  },
  encryptionInformation: {
    path: 'encryptionInformation',
    names: ['type', 'policy', 'keyAccess', 'method', 'integrityInformation'],
  },
  keyAccessObject: {
    path: 'encryptionInformation.keyAccess[]',
    names: [
      'type',
      'url',
      'protocol',
      'wrappedKey',
      'policyBinding',
      'encryptedMetadata',
      'kid',
      'sid',
      'schemaVersion',
      'ephemeralPublicKey',
    ],
  },
  policyBinding: {
    path: 'encryptionInformation.keyAccess[].policyBinding',
    names: ['alg', 'hash'],
  },
  method: { path: 'encryptionInformation.method', names: ['algorithm', 'iv', 'isStreamable'] },
  integrityInformation: {
    path: 'encryptionInformation.integrityInformation',
    names: [
      'rootSignature',
      'segmentHashAlg',
      'segmentSizeDefault',
      'encryptedSegmentSizeDefault',
      'segments',
    ],
  },
  rootSignature: {
    path: 'encryptionInformation.integrityInformation.rootSignature',
    names: ['alg', 'sig'],
  },
  segment: {
    path: 'encryptionInformation.integrityInformation.segments[]',
    names: ['hash', 'segmentSize', 'encryptedSegmentSize'],
  },
  assertion: {
    path: 'assertions[]',
    names: ['id', 'type', 'scope', 'appliesToState', 'statement', 'binding'],
  },
  statement: { path: 'assertions[].statement', names: ['format', 'schema', 'value'] },
  binding: { path: 'assertions[].binding', names: ['method', 'signature', 'bdo'] },
};

/**
 * Case variants that R1 tolerates, by level: java-sdk up to v0.7.5 wrote
 * `IsStreamable`. Two fold-equal names in one object are still rejected.
 */
const CASE_VARIANT_EXCEPTIONS: Partial<Record<ObjectLevel, readonly string[]>> = {
  method: ['IsStreamable'],
};

/**
 * The modelled names and tolerated case variants by level path, as in the
 * contract's Section 3.2 table (`''` is the manifest root, `[]` an array
 * element). For conformance tests.
 */
export const MODELLED_NAMES: Readonly<Record<string, readonly string[]>> = Object.fromEntries(
  Object.values(MODELLED).map(({ path, names }) => [path, names])
);
export const CASE_VARIANT_EXCEPTIONS_BY_PATH: Readonly<Record<string, readonly string[]>> =
  Object.fromEntries(
    Object.entries(CASE_VARIANT_EXCEPTIONS).map(([level, names]) => [
      MODELLED[level as ObjectLevel].path,
      names,
    ])
  );

/** Where each modelled member leads, when its value is a container. */
const CHILDREN: Partial<Record<ObjectLevel, Record<string, Level>>> = {
  manifest: {
    assertions: 'assertions',
    encryptionInformation: 'encryptionInformation',
    payload: 'payload',
  },
  encryptionInformation: {
    keyAccess: 'keyAccess',
    method: 'method',
    integrityInformation: 'integrityInformation',
  },
  keyAccessObject: { policyBinding: 'policyBinding' },
  integrityInformation: { rootSignature: 'rootSignature', segments: 'segments' },
  assertion: { statement: 'statement', binding: 'binding' },
};

/** The level of each array's elements. */
const ELEMENTS: Record<ArrayLevel, ObjectLevel> = {
  keyAccess: 'keyAccessObject',
  segments: 'segment',
  assertions: 'assertion',
};

function isObjectLevel(level: Level): level is ObjectLevel {
  return Object.prototype.hasOwnProperty.call(MODELLED, level);
}

function isArrayLevel(level: Level): level is ArrayLevel {
  return Object.prototype.hasOwnProperty.call(ELEMENTS, level);
}

/**
 * Fold a member name as Go's `strings.EqualFold` matches it against ASCII:
 * ASCII letters, U+017F (long s), and U+212A (Kelvin sign) to lower case,
 * every other code unit unchanged. Not `toLowerCase`, which also folds names
 * such as `ıd`.
 */
function fold(name: string): string {
  let folded = '';
  for (let i = 0; i < name.length; i++) {
    const c = name.charCodeAt(i);
    folded +=
      c >= 0x41 && c <= 0x5a
        ? String.fromCharCode(c + 0x20)
        : c === 0x17f
          ? 's'
          : c === 0x212a
            ? 'k'
            : name[i];
  }
  return folded;
}

/** Each level's modelled names by their folded form. */
const MODELLED_BY_FOLD = Object.fromEntries(
  Object.entries(MODELLED).map(([level, { names }]) => [
    level,
    new Map(names.map((name) => [fold(name), name])),
  ])
) as Record<ObjectLevel, Map<string, string>>;

/**
 * Whether `name` is a case variant of the ASCII member name `modelled`: not
 * equal to it, but equal after {@link fold}.
 */
export function isCaseVariant(name: string, modelled: string): boolean {
  return name !== modelled && fold(name) === fold(modelled);
}

type AssertionContext = {
  /** How many exact `id` members the assertion object has had so far. */
  idCount: number;
  /** The exact `id`, when there is exactly one and it is a valid nonempty string. */
  id?: string;
};

type Frame = {
  object: boolean;
  level: Level;
  ctx?: AssertionContext;
  keys?: Set<string>;
  /** At modelled levels, the first name seen for each folded form. */
  folded?: Map<string, string>;
};

/** The contract failure reported for a document. */
export type StrictJsonFailure = {
  reason: AssertionFailureReason;
  detail: string;
  /** The exact `id` of the assertion the failure is in, when it has a valid one. */
  assertionId?: string;
};

export type StrictJsonScan =
  | { ok: true; failure?: undefined; syntaxError?: undefined }
  | { ok: false; failure: StrictJsonFailure; syntaxError?: undefined }
  | { ok: false; failure?: undefined; syntaxError: string };

class JsonSyntaxError extends Error {}

/** Quote an untrusted member name for an error message, truncating long ones. */
function describeName(name: string): string {
  return JSON.stringify(name.length > 64 ? `${name.slice(0, 64)}...` : name);
}

function childLevel(parent: Level, name: string): Level {
  if (!isObjectLevel(parent)) {
    return 'other';
  }
  const children = CHILDREN[parent];
  return children && Object.prototype.hasOwnProperty.call(children, name)
    ? children[name]
    : 'other';
}

const QUOTE = 0x22;
const BACKSLASH = 0x5c;
const COMMA = 0x2c;
const COLON = 0x3a;
const LBRACE = 0x7b;
const RBRACE = 0x7d;
const LBRACKET = 0x5b;
const RBRACKET = 0x5d;
const MINUS = 0x2d;

function isDigit(c: number): boolean {
  return c >= 0x30 && c <= 0x39;
}

function hexValue(c: number): number {
  if (c >= 0x30 && c <= 0x39) return c - 0x30;
  if (c >= 0x41 && c <= 0x46) return c - 0x37;
  if (c >= 0x61 && c <= 0x66) return c - 0x57;
  return -1;
}

/**
 * Check `text` (RFC 8259 JSON) against spec Section 3 without building a tree.
 *
 * Like the checks in spec Section 8 step 1, failures are reported in this
 * order: a syntax error; else the first duplicate member; else the first case
 * variant; else the first I-JSON violation inside an assertion. The whole text
 * is scanned, so the failing assertion's `id` is known even when it comes
 * after the failure.
 */
export function scanStrictJson(text: string, root: StrictJsonRoot): StrictJsonScan {
  const n = text.length;
  let i = 0;
  type Noted = { reason: AssertionFailureReason; detail: string; ctx?: AssertionContext };
  const firstOf: Partial<Record<AssertionFailureReason, Noted>> = {};
  let stringProblem: string | undefined;
  const stack: Frame[] = [];

  const note = (reason: AssertionFailureReason, detail: string, ctx?: AssertionContext) => {
    firstOf[reason] ??= { reason, detail, ctx };
  };
  const syntax = (message: string): never => {
    throw new JsonSyntaxError(`${message} at offset ${i}`);
  };
  const skipWhitespace = () => {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x0a || c === 0x0d || c === 0x09) {
        i++;
      } else {
        break;
      }
    }
  };

  /**
   * Read the string starting at `text[i]`. Returns it decoded when `decode` is
   * set. When `checkUnicode` is set, leaves the first surrogate or
   * noncharacter problem in `stringProblem`.
   */
  const readString = (decode: boolean, checkUnicode: boolean): string => {
    i++; // opening quote
    stringProblem = undefined;
    const parts: string[] = [];
    let segmentStart = i;
    let pendingHigh = -1;
    for (;;) {
      if (i >= n) {
        syntax('unterminated string');
      }
      const c = text.charCodeAt(i);
      let unit: number;
      if (c === QUOTE) {
        if (decode) {
          parts.push(text.slice(segmentStart, i));
        }
        i++;
        if (checkUnicode && pendingHigh >= 0) {
          stringProblem ??= 'a lone surrogate';
        }
        return decode ? parts.join('') : '';
      } else if (c === BACKSLASH) {
        if (decode) {
          parts.push(text.slice(segmentStart, i));
        }
        const e = text.charCodeAt(i + 1);
        switch (e) {
          case QUOTE:
          case BACKSLASH:
          case 0x2f: // solidus
            unit = e;
            break;
          case 0x62: // b
            unit = 0x08;
            break;
          case 0x66: // f
            unit = 0x0c;
            break;
          case 0x6e: // n
            unit = 0x0a;
            break;
          case 0x72: // r
            unit = 0x0d;
            break;
          case 0x74: // t
            unit = 0x09;
            break;
          case 0x75: {
            // u
            unit = 0;
            for (let k = 2; k < 6; k++) {
              const h = hexValue(text.charCodeAt(i + k));
              if (h < 0) {
                syntax('invalid \\u escape');
              }
              unit = (unit << 4) | h;
            }
            i += 4;
            break;
          }
          default:
            return syntax('invalid escape');
        }
        i += 2;
        if (decode) {
          parts.push(String.fromCharCode(unit));
        }
        segmentStart = i;
      } else {
        if (c < 0x20) {
          syntax('unescaped control character in string');
        }
        unit = c;
        i++;
      }
      if (!checkUnicode) {
        continue;
      }
      if (pendingHigh >= 0) {
        if (unit >= 0xdc00 && unit <= 0xdfff) {
          const codePoint = ((pendingHigh - 0xd800) << 10) + (unit - 0xdc00) + 0x10000;
          pendingHigh = -1;
          if ((codePoint & 0xfffe) === 0xfffe) {
            stringProblem ??= 'a noncharacter';
          }
          continue;
        }
        stringProblem ??= 'a lone surrogate';
        pendingHigh = -1;
      }
      if (unit >= 0xd800 && unit <= 0xdbff) {
        pendingHigh = unit;
      } else if (unit >= 0xdc00 && unit <= 0xdfff) {
        stringProblem ??= 'a lone surrogate';
      } else if ((unit >= 0xfdd0 && unit <= 0xfdef) || unit === 0xfffe || unit === 0xffff) {
        stringProblem ??= 'a noncharacter';
      }
    }
  };

  /** Read the number starting at `text[i]`; returns whether it is a finite double. */
  const readNumber = (): boolean => {
    const start = i;
    if (text.charCodeAt(i) === MINUS) {
      i++;
    }
    const lead = text.charCodeAt(i);
    if (lead === 0x30) {
      i++;
    } else if (lead >= 0x31 && lead <= 0x39) {
      while (isDigit(text.charCodeAt(i))) i++;
    } else {
      syntax('invalid number');
    }
    if (text.charCodeAt(i) === 0x2e) {
      i++;
      if (!isDigit(text.charCodeAt(i))) {
        syntax('invalid number');
      }
      while (isDigit(text.charCodeAt(i))) i++;
    }
    const e = text.charCodeAt(i);
    if (e === 0x65 || e === 0x45) {
      i++;
      const sign = text.charCodeAt(i);
      if (sign === 0x2b || sign === MINUS) {
        i++;
      }
      if (!isDigit(text.charCodeAt(i))) {
        syntax('invalid number');
      }
      while (isDigit(text.charCodeAt(i))) i++;
    }
    return Number.isFinite(Number(text.slice(start, i)));
  };

  // The value about to be read: the level it takes if it is a container, the
  // assertion it is inside, and whether it is an assertion's exact `id`.
  let nextLevel: Level = root === 'json' ? 'other' : root;
  let nextCtx: AssertionContext | undefined;
  let valueIsId = false;
  let state: 'value' | 'member' | 'after' = 'value';
  let syntaxError: string | undefined;

  try {
    for (;;) {
      if (state === 'value') {
        skipWhitespace();
        const c = text.charCodeAt(i);
        const idCtx = valueIsId ? nextCtx : undefined;
        valueIsId = false;
        if (idCtx && c !== QUOTE) {
          // Not a string, so the assertion has no valid id.
          idCtx.idCount++;
          idCtx.id = undefined;
        }
        if (c === LBRACE) {
          i++;
          const level: Level = isObjectLevel(nextLevel) ? nextLevel : 'other';
          const ctx = level === 'assertion' ? { idCount: 0 } : nextCtx;
          stack.push({
            object: true,
            level,
            ctx,
            keys: new Set<string>(),
            ...(level !== 'other' && { folded: new Map<string, string>() }),
          });
          skipWhitespace();
          if (text.charCodeAt(i) === RBRACE) {
            i++;
            stack.pop();
            state = 'after';
          } else {
            state = 'member';
          }
        } else if (c === LBRACKET) {
          i++;
          const level: Level = isArrayLevel(nextLevel) ? nextLevel : 'other';
          stack.push({ object: false, level, ctx: nextCtx });
          skipWhitespace();
          if (text.charCodeAt(i) === RBRACKET) {
            i++;
            stack.pop();
            state = 'after';
          } else {
            nextLevel = isArrayLevel(level) ? ELEMENTS[level] : 'other';
            state = 'value';
          }
        } else if (c === QUOTE) {
          const value = readString(!!idCtx, !!nextCtx);
          if (stringProblem) {
            note('invalid-json', `string contains ${stringProblem}`, nextCtx);
          }
          if (idCtx) {
            idCtx.idCount++;
            idCtx.id = idCtx.idCount === 1 && !stringProblem && value ? value : undefined;
          }
          state = 'after';
        } else {
          if (c === MINUS || isDigit(c)) {
            if (!readNumber() && nextCtx) {
              note('invalid-json', 'number is outside the IEEE 754 double range', nextCtx);
            }
          } else if (text.startsWith('true', i) || text.startsWith('null', i)) {
            i += 4;
          } else if (text.startsWith('false', i)) {
            i += 5;
          } else {
            syntax(i >= n ? 'unexpected end of input' : 'unexpected character');
          }
          state = 'after';
        }
      } else if (state === 'member') {
        const frame = stack[stack.length - 1];
        skipWhitespace();
        if (text.charCodeAt(i) !== QUOTE) {
          syntax('expected a member name');
        }
        const name = readString(true, !!frame.ctx);
        if (stringProblem) {
          note('invalid-json', `member name contains ${stringProblem}`, frame.ctx);
        }
        if (frame.keys!.has(name)) {
          note('duplicate-member', `duplicate member ${describeName(name)}`, frame.ctx);
        } else {
          frame.keys!.add(name);
        }
        if (frame.folded && isObjectLevel(frame.level)) {
          const folded = fold(name);
          // R1: a case variant of a name modelled at this level.
          const modelled = MODELLED_BY_FOLD[frame.level].get(folded);
          if (
            modelled !== undefined &&
            modelled !== name &&
            !CASE_VARIANT_EXCEPTIONS[frame.level]?.includes(name)
          ) {
            note(
              'ambiguous-member',
              `member ${describeName(name)} is a case variant of ${JSON.stringify(modelled)}`,
              frame.ctx
            );
          }
          // R2: two members whose names are case variants of each other.
          const earlier = frame.folded.get(folded);
          if (earlier === undefined) {
            frame.folded.set(folded, name);
          } else if (earlier !== name) {
            note(
              'ambiguous-member',
              `members ${describeName(earlier)} and ${describeName(name)} differ only in case`,
              frame.ctx
            );
          }
        }
        skipWhitespace();
        if (text.charCodeAt(i) !== COLON) {
          syntax('expected a colon');
        }
        i++;
        nextLevel = childLevel(frame.level, name);
        nextCtx = frame.ctx;
        valueIsId = frame.level === 'assertion' && name === 'id';
        state = 'value';
      } else {
        // A value just ended.
        skipWhitespace();
        if (!stack.length) {
          if (i !== n) {
            syntax('unexpected data after the top-level value');
          }
          break;
        }
        const frame = stack[stack.length - 1];
        const c = text.charCodeAt(i);
        if (c === COMMA) {
          i++;
          if (frame.object) {
            state = 'member';
          } else {
            nextLevel = isArrayLevel(frame.level) ? ELEMENTS[frame.level] : 'other';
            nextCtx = frame.ctx;
            state = 'value';
          }
        } else if (c === (frame.object ? RBRACE : RBRACKET)) {
          i++;
          stack.pop();
        } else {
          syntax(i >= n ? 'unexpected end of input' : 'expected a comma or a closing bracket');
        }
      }
    }
  } catch (e) {
    if (!(e instanceof JsonSyntaxError)) {
      throw e;
    }
    syntaxError = e.message;
  }

  if (syntaxError !== undefined) {
    return { ok: false, syntaxError };
  }
  const first =
    firstOf['duplicate-member'] ?? firstOf['ambiguous-member'] ?? firstOf['invalid-json'];
  if (first) {
    const { reason, detail, ctx } = first;
    return {
      ok: false,
      failure: ctx?.id === undefined ? { reason, detail } : { reason, detail, assertionId: ctx.id },
    };
  }
  return { ok: true };
}

// With the u flag a valid surrogate pair matches as one supplementary code
// point, so only lone surrogates fall in this range.
const LONE_SURROGATE = /[\uD800-\uDFFF]/u;

/**
 * Serialize a JSON value with the JSON Canonicalization Scheme (RFC 8785).
 *
 * Accepts only what `JSON.parse` produces: `null`, booleans, finite numbers,
 * well-formed strings, arrays, and plain objects. Object members whose value is
 * `undefined` are skipped, as `JSON.stringify` does. Anything else throws a
 * `TypeError` rather than being coerced; in particular a member named `toJSON`
 * is serialized like any other.
 */
export function canonicalJson(value: unknown): string {
  // Appends to one buffer, sorting each object's names once: O(n log n) in
  // members and linear in size, whatever the nesting.
  const out: string[] = [];
  const write = (v: unknown): void => {
    switch (typeof v) {
      case 'string':
        if (LONE_SURROGATE.test(v)) {
          throw new TypeError('JCS: string contains a lone surrogate');
        }
        out.push(JSON.stringify(v));
        return;
      case 'boolean':
        out.push(v ? 'true' : 'false');
        return;
      case 'number':
        if (!Number.isFinite(v)) {
          throw new TypeError('JCS: number is not finite');
        }
        // ECMAScript number serialization is the one RFC 8785 specifies.
        out.push(JSON.stringify(v));
        return;
      case 'object': {
        if (v === null) {
          out.push('null');
          return;
        }
        if (Array.isArray(v)) {
          out.push('[');
          v.forEach((element: unknown, i) => {
            if (i) {
              out.push(',');
            }
            write(element);
          });
          out.push(']');
          return;
        }
        const prototype = Object.getPrototypeOf(v) as unknown;
        if (prototype !== Object.prototype && prototype !== null) {
          throw new TypeError('JCS: only plain objects can be canonicalized');
        }
        const record = v as Record<string, unknown>;
        // The default sort compares UTF-16 code units, as RFC 8785 requires.
        const names = Object.keys(record)
          .filter((k) => record[k] !== undefined)
          .sort();
        out.push('{');
        names.forEach((name, i) => {
          if (LONE_SURROGATE.test(name)) {
            throw new TypeError('JCS: member name contains a lone surrogate');
          }
          out.push(i ? ',' : '', JSON.stringify(name), ':');
          write(record[name]);
        });
        out.push('}');
        return;
      }
      default:
        throw new TypeError(`JCS: cannot canonicalize a value of type ${typeof v}`);
    }
  };
  write(value);
  return out.join('');
}
