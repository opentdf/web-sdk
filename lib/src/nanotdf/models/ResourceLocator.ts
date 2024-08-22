import { fromURLProtocol, ProtocolEnum } from '../enum/ProtocolEnum.js';
import {
  ResourceLocatorIdentifierEnum,
  length as rLength,
  idType as ridType,
} from '../enum/ResourceLocatorIdentifierEnum.js';

/**
 *
 * The Resource Locator is a way for the nanotdf to represent references to external resources in as succinct a format
 * as possible.
 *
 * | Section       | Minimum Length (B) | Maximum Length (B) |
 * |---------------|--------------------|--------------------|
 * | Protocol Enum | 1                  | 1                  |
 * | Body Length   | 1                  | 1                  |
 * | Body          | 1                  | 255                |
 * | Identifier    | 0                  | n                  |
 *
 * @link https://github.com/virtru/nanotdf/blob/master/spec/index.md#3312-kas
 * @link https://github.com/virtru/nanotdf/blob/master/spec/index.md#341-resource-locator
 */
export default class ResourceLocator {
  readonly protocol: ProtocolEnum;
  readonly lengthOfBody: number;
  readonly body: string;
  readonly identifier: string;
  readonly identifierType: ResourceLocatorIdentifierEnum = ResourceLocatorIdentifierEnum.None;
  readonly offset: number = 0;

  static readonly PROTOCOL_OFFSET = 0;
  static readonly PROTOCOL_LENGTH = 1;
  static readonly LENGTH_OFFSET = 1;
  static readonly LENGTH_LENGTH = 1;
  static readonly BODY_OFFSET = 2;
  static readonly IDENTIFIER_0_BYTE: number = 0 << 4; // 0
  static readonly IDENTIFIER_2_BYTE: number = 1 << 4; // 16
  static readonly IDENTIFIER_8_BYTE: number = 2 << 4; // 32
  static readonly IDENTIFIER_32_BYTE: number = 3 << 4; // 48

  static parse(url: string, identifier: string = ''): ResourceLocator {
    const [protocol, body] = new URL(url).href.split('://');
    const protocolByte = fromURLProtocol(protocol);
    const bodyArray = new TextEncoder().encode(body);
    const bodyLength = bodyArray.length;

    const identifierArray = new TextEncoder().encode(identifier);
    const identifierType = ridType(identifierArray.length);
    const identifierPaddedLength = rLength(identifierType);

    // Buffer to hold the protocol, length of body, body, and identifierPadded
    const buffer = new Uint8Array(1 + 1 + bodyLength + identifierPaddedLength);
    buffer[0] = (identifierType << 4) | protocolByte;

    if (bodyLength > 255) {
      throw new Error(`url too long, max length 255 (excluding protocol)`);
    }
    buffer[1] = bodyLength;
    buffer.set(bodyArray, 2);

    // add padded identifier
    if (identifierPaddedLength != ResourceLocatorIdentifierEnum.None) {
      buffer.set(identifierArray, 2 + bodyLength);
    }

    return new ResourceLocator(buffer);
  }

  constructor(buff: Uint8Array) {
    // Protocol
    const protocolAndIdType = buff[ResourceLocator.PROTOCOL_OFFSET];
    // Length of body
    this.lengthOfBody = buff[ResourceLocator.LENGTH_OFFSET];
    // Body as utf8 string
    const decoder = new TextDecoder();
    this.body = decoder.decode(
      buff.subarray(ResourceLocator.BODY_OFFSET, ResourceLocator.BODY_OFFSET + this.lengthOfBody)
    );
    // identifier
    this.identifierType = (protocolAndIdType >> 4) & 0xf;
    switch (this.identifierType) {
      case ResourceLocatorIdentifierEnum.None:
        // noop
        break;
      case ResourceLocatorIdentifierEnum.TwoBytes:
      case ResourceLocatorIdentifierEnum.EightBytes:
      case ResourceLocatorIdentifierEnum.ThirtyTwoBytes:
        const start = ResourceLocator.BODY_OFFSET + this.lengthOfBody;
        const end = start + rLength(this.identifierType);
        const subarray = buff.subarray(start, end);
        // Remove padding (assuming the padding is null bytes, 0x00)
        const trimmedSubarray = subarray.filter((byte) => byte !== 0x00);
        this.identifier = decoder.decode(trimmedSubarray);
        break;
      default:
        throw new Error(`unsupported key identifier type [${this.identifierType}]`);
    }
    this.offset =
      ResourceLocator.PROTOCOL_LENGTH +
      ResourceLocator.LENGTH_LENGTH +
      this.lengthOfBody +
      rLength(this.identifierType);
  }

  /**
   * Length
   *
   * @returns { number } Length of resource locator
   */
  get length(): number {
    return (
      // Protocol
      1 +
      // Length of the body( 1 byte)
      1 +
      // Content length
      this.body.length +
      // Identifier length
      rLength(this.identifierType)
    );
  }

  get url(): string | never {
    switch (this.protocol) {
      case ProtocolEnum.Http:
        return 'http://' + this.body;
      case ProtocolEnum.Https:
        return 'https://' + this.body;
      default:
        throw new Error('Resource locator protocol is not supported.');
    }
  }

  /**
   * Return the contents of the Resource Locator in buffer
   */
  toBuffer(): Uint8Array {
    const buffer = new Uint8Array(2 + this.body.length + rLength(this.identifierType));
    buffer.set([this.protocol | (this.identifierType << 4)], 0);
    buffer.set([this.lengthOfBody], 1);
    buffer.set(new TextEncoder().encode(this.body), 2);
    if (this.identifier) {
      buffer.set(new TextEncoder().encode(this.identifier), 2 + this.body.length);
    }
    return buffer;
  }

  /**
   * Get URL
   *
   * Construct URL from ResourceLocator or throw error
   */
  getUrl(): string | never {
    let protocol: string;
    // protocolIndex get the first four bits
    const protocolIndex: number = this.protocol & 0xf;
    if (protocolIndex === ProtocolEnum.Http) {
      protocol = 'http';
    } else if (protocolIndex === ProtocolEnum.Https) {
      protocol = 'https';
    } else {
      throw new Error(`Cannot create URL from protocol, "${ProtocolEnum[this.protocol]}"`);
    }
    return `${protocol}://${this.body}`;
  }

  /**
   * Get Identifier
   *
   * Returns the identifier of the ResourceLocator or an empty string if no identifier is present.
   * @returns { string } Identifier of the resource locator.
   */
  getIdentifier(): string {
    return this.identifier || '';
  }
}
