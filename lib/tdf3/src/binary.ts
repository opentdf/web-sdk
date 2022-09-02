/* eslint-disable max-classes-per-file */

/**
 * Provides a binary type that can be initialized with many different forms of
 * data
 *
 * TODO(PLAT-1230): Deprecate this.
 * 1. asX methods sometimes return copies, sometimes references.
 * 2. We should be using ArrayBuffer/TypedArray for performance/correctness.
 * 3. It is confusing how we represent data in Strings, historically leading to
 *    encoding errors.
 */
export abstract class Binary {
  /**
   * Initializes the binary class from the string
   */
  static fromString(data: string): Binary {
    return new StringBinary(data);
  }

  /**
   * Initializes the binary class from an arrayBuffer
   */
  static fromArrayBuffer(data: ArrayBuffer): Binary {
    return new ArrayBufferBinary(data);
  }

  /**
   * Initializes the binary class from an array of bytes
   */
  static fromByteArray(data: number[]): Binary {
    return new ByteArrayBinary(data);
  }

  /**
   * Initializes the binary class from a node-style Buffer object.
   */
  static fromBuffer(data: Buffer): Binary {
    return new BufferBinary(data);
  }

  isArrayBuffer(): boolean {
    return false;
  }

  isBuffer(): boolean {
    return false;
  }

  isByteArray(): boolean {
    return false;
  }

  isString(): boolean {
    return false;
  }

  abstract asArrayBuffer(): ArrayBuffer;

  abstract asBuffer(): Buffer;

  abstract asByteArray(): number[];

  abstract asString(): string;

  abstract length(): number;

  abstract slice(start: number, end?: number): Binary;
}

function adjustSliceParams(length: number, start: number, end?: number): [number, number?] {
  if (start < 0) {
    start = length + start;
  }
  if (end && end < 0) {
    end = length + end;
  }
  return [start, end];
}

class ArrayBufferBinary extends Binary {
  value: ArrayBuffer;

  constructor(value: ArrayBuffer) {
    super();
    this.value = value;
  }

  asArrayBuffer(): ArrayBuffer {
    return this.value;
  }

  asBuffer(): Buffer {
    return Buffer.from(this.value);
  }

  asByteArray(): number[] {
    const uint8Array = new Uint8Array(this.value);
    // Initialize array
    const byteArray = new Array(uint8Array.length);
    for (let i = 0; i < byteArray.length; i++) {
      byteArray[i] = uint8Array[i];
    }
    return byteArray;
  }

  asString(): string {
    const uint8Array = new Uint8Array(this.value);
    let str = '';
    for (let i = 0; i < uint8Array.length; i++) {
      str = str + String.fromCharCode(uint8Array[i]);
    }
    return str;
  }

  isArrayBuffer(): boolean {
    return true;
  }

  length(): number {
    return this.value.byteLength;
  }

  slice(start: number, end?: number): Binary {
    const [s, e] = adjustSliceParams(this.value.byteLength, start, end);
    return new ArrayBufferBinary(this.value.slice(s, e));
  }
}

class BufferBinary extends Binary {
  value: Buffer;

  constructor(value: Buffer) {
    super();
    this.value = value;
  }

  asArrayBuffer(): ArrayBuffer {
    if (this.value.buffer) {
      return this.value.buffer.slice(
        this.value.byteOffset,
        this.value.byteOffset + this.value.byteLength
      );
    }

    const arrayBuffer = new ArrayBuffer(this.value.length);
    const bufferView = new Uint8Array(arrayBuffer);
    for (let i = 0; i < this.value.length; i++) {
      bufferView[i] = this.value[i];
    }
    return arrayBuffer;
  }

  asBuffer(): Buffer {
    return this.value;
  }

  asByteArray(): number[] {
    const byteArray = new Array(this.value.length);

    for (let i = 0; i < byteArray.length; i++) {
      byteArray[i] = this.value[i];
    }

    return byteArray;
  }

  asString(): string {
    return this.value.toString('binary');
  }

  isBuffer(): boolean {
    return true;
  }

  length(): number {
    return this.value.length;
  }

  slice(start: number, end?: number): Binary {
    const [s, e] = adjustSliceParams(this.value.length, start, end);
    return new BufferBinary(this.value.slice(s, e));
  }
}

class ByteArrayBinary extends Binary {
  value: number[];

  constructor(value: number[]) {
    super();
    this.value = value;
  }

  asArrayBuffer(): ArrayBuffer {
    const buf = Buffer.from(this.value);
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  }

  asBuffer(): Buffer {
    return Buffer.from(this.value);
  }

  asByteArray(): number[] {
    return this.value;
  }

  asString(): string {
    return Buffer.from(this.value).toString();
  }

  isByteArray(): boolean {
    return true;
  }

  length(): number {
    return this.value.length;
  }

  slice(start: number, end?: number): Binary {
    const [s, e] = adjustSliceParams(this.length(), start, end);
    return new ByteArrayBinary(this.value.slice(s, e));
  }
}

class StringBinary extends Binary {
  value: string;

  constructor(value: string) {
    super();
    this.value = value;
  }

  asArrayBuffer(): ArrayBuffer {
    const { length } = this.value;
    const buffer = new ArrayBuffer(length);
    const bufferView = new Uint8Array(buffer);
    for (let i = 0; i < length; i++) {
      bufferView[i] = this.value.charCodeAt(i);
    }
    return buffer;
  }

  asBuffer(): Buffer {
    return Buffer.from(this.value, 'binary');
  }

  asByteArray(): number[] {
    const byteArray = [];
    for (let i = 0; i < this.value.length; i++) {
      byteArray.push(this.value.charCodeAt(i));
    }
    return byteArray;
  }

  asString(): string {
    return this.value;
  }

  isString(): boolean {
    return true;
  }

  length(): number {
    return this.value.length;
  }

  slice(start: number, end?: number): Binary {
    const [s, e] = adjustSliceParams(this.value.length, start, end);
    return new StringBinary(this.value.substring(s, e));
  }
}
