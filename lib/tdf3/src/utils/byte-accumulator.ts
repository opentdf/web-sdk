/**
 * Appends fixed-size byte runs into one contiguous buffer.
 *
 * The root signature is computed over the concatenation of every segment hash,
 * and both the write and read paths used to build that by collecting one
 * `Uint8Array` per segment and joining them through a `Blob`. At 3.3M segments
 * (50 TiB at 16 MiB, the target configuration) that is 3.3M live typed-array
 * objects -- several hundred MB of object overhead on top of the ~105 MB of
 * actual digest -- plus a full extra copy through the `Blob`. Writing straight
 * into one buffer keeps only the digest bytes.
 *
 * WebCrypto has no incremental HMAC, so the concatenation genuinely has to
 * exist as one buffer before it can be signed; and the same bytes are the
 * message assertions are bound to. This bounds the cost of producing it, it
 * does not eliminate it.
 */
export class ByteAccumulator {
  #buffer: Uint8Array;
  #length = 0;

  /**
   * @param expectedBytes total bytes expected, when known. Sizing exactly
   * avoids the doubling growth, whose transient peak would otherwise be up to
   * three times the final buffer.
   */
  constructor(expectedBytes = 0) {
    this.#buffer = new Uint8Array(Math.max(expectedBytes, 64));
  }

  get length(): number {
    return this.#length;
  }

  push(bytes: Uint8Array): void {
    this.#reserve(this.#length + bytes.length);
    this.#buffer.set(bytes, this.#length);
    this.#length += bytes.length;
  }

  /**
   * The accumulated bytes. A view, not a copy -- valid until the next
   * {@link push}, which is enough for every caller here since they all
   * accumulate fully and then read once.
   */
  subarray(): Uint8Array {
    return this.#buffer.subarray(0, this.#length);
  }

  #reserve(capacity: number): void {
    if (capacity <= this.#buffer.length) {
      return;
    }
    let grown = this.#buffer.length;
    while (grown < capacity) {
      grown *= 2;
    }
    const replacement = new Uint8Array(grown);
    replacement.set(this.#buffer.subarray(0, this.#length));
    this.#buffer = replacement;
  }
}
