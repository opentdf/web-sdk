import { base64 } from '../encodings/index.js';
import Header from './models/Header.js';
import Payload from './models/Payload.js';
import Signature from './models/Signature.js';
import EncodingEnum from './enum/EncodingEnum.js';
import { ConfigurationError, InvalidFileError } from '../errors.js';

// Defaults when none set during encryption

export default class NanoTDF {
  // Add encodings to the NanoTDF class for easy access
  static Encodings: typeof EncodingEnum = EncodingEnum;
  static Header = Header;
  static Payload = Payload;
  static Signature = Signature;

  public header: Header;
  public payload: Payload;

  // TODO: This should be optional
  public signature?: Signature;

  static from(
    content: ArrayBufferLike | string,
    encoding?: EncodingEnum,
    legacyTDF = false
  ): NanoTDF {
    // If we don't assign an empty array buffer then TS reports buffer as unassigned
    let buffer;
    if (typeof content === 'string') {
      if (!encoding || encoding === EncodingEnum.Base64) {
        buffer = base64.decodeArrayBuffer(content);
      } else {
        throw new ConfigurationError(`Unsupported encoding: ${encoding}`);
      }
    }
    // Handle Uint8Array types
    else if (ArrayBuffer.isView(content) || content instanceof ArrayBuffer) {
      buffer = content;
    } else {
      throw new ConfigurationError(`unsupported content type`);
    }

    const dataView = new Uint8Array(buffer);
    let offset = 0;

    // Header
    const { header, offset: headerOffset } = Header.parse(dataView.subarray(offset));
    offset += headerOffset;

    // Payload
    const { payload, offset: payloadOffset } = Payload.parse(
      header,
      dataView.subarray(offset),
      legacyTDF
    );
    offset += payloadOffset;

    // Signature
    const { signature, offset: signatureOffset } = Signature.parse(
      header,
      dataView.subarray(offset)
    );
    offset += signatureOffset;

    // Singature checking
    if (!header.hasSignature && signature.length > 0) {
      throw new InvalidFileError("Found signature when there shouldn't be one");
    }
    if (header.hasSignature && signature.length === 0) {
      throw new InvalidFileError('Could not find signature');
    }

    return new NanoTDF(header, payload, signature);
  }

  constructor(header: Header, payload: Payload, signature?: Signature) {
    this.header = header;
    this.payload = payload;
    this.signature = signature;
  }

  /**
   * Return the content of nano tdf as binary buffer
   */
  toBuffer(): ArrayBuffer {
    let offset = 0;

    const lengthOfSignature = this.signature && this.signature.length ? this.signature.length : 0;
    const lengthOfTDF = this.header.length + this.payload.length + lengthOfSignature;

    const buffer = new ArrayBuffer(lengthOfTDF);

    // Write the header
    const headerBufferView = new Uint8Array(buffer, 0, this.header.length);
    this.header.copyToBuffer(headerBufferView);
    offset += headerBufferView.length;

    // Write the payload
    const payloadBufferView = new Uint8Array(buffer, offset, this.payload.length);
    this.payload.copyToBuffer(payloadBufferView);
    offset += payloadBufferView.length;

    // Write the signature
    if (this.header.hasSignature && this.signature) {
      const signatureBufferView = new Uint8Array(buffer, offset, lengthOfSignature);
      this.signature.copyToBuffer(signatureBufferView);
    }

    return buffer;
  }

  /**
   * Return the content of nano tdf as base64 string
   */
  toBase64(): string {
    const arrayBuffer = this.toBuffer();
    return base64.encodeArrayBuffer(arrayBuffer);
  }
}
