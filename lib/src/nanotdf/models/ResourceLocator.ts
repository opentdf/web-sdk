import ProtocolEnum from '../enum/ProtocolEnum.js';
import ResourceLocatorIdentifierEnum from '../enum/ResourceLocatorIdentifierEnum.js';

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
  readonly identifierType: ResourceLocatorIdentifierEnum;
  readonly offset: number = 0;

  static readonly PROTOCOL_OFFSET = 0;
  static readonly PROTOCOL_LENGTH = 1;
  static readonly LENGTH_OFFSET = 1;
  static readonly LENGTH_LENGTH = 1;
  static readonly BODY_OFFSET = 2;

  static parse(url: string, identifier: string = ''): ResourceLocator {
    const [protocol, body] = url.split('://');
    const bodyLength = body.length;
    const identifierLength = identifier.length;
    let identifierPaddedLength = 0;
    // protocol and identifier byte
    const protocolIdentifierByte = new Uint8Array(1);
    if (protocol.toLowerCase() == 'http') {
      protocolIdentifierByte[0] = protocolIdentifierByte[0] & 0x0f;
    } else if (protocol.toLowerCase() == 'https') {
      protocolIdentifierByte[0] = (protocolIdentifierByte[0] & 0x0f) | 0b0010;
    } else {
      throw new Error('Resource locator protocol is not supported.');
    }
    if (identifierLength === 0) {
      protocolIdentifierByte[0] = (protocolIdentifierByte[0] & 0xf0) | 0b0000;
    } else if (identifierLength <= 2) {
      protocolIdentifierByte[0] = (protocolIdentifierByte[0] & 0xf0) | 0b0010;
      identifierPaddedLength = ResourceLocatorIdentifierEnum.TwoBytes.valueOf();
    } else if (identifierLength <= 8) {
      protocolIdentifierByte[0] = (protocolIdentifierByte[0] & 0xf0) | 0b0100;
      identifierPaddedLength = ResourceLocatorIdentifierEnum.EightBytes.valueOf();
    } else if (identifierLength <= 32) {
      protocolIdentifierByte[0] = (protocolIdentifierByte[0] & 0xf0) | 0b1000;
      identifierPaddedLength = ResourceLocatorIdentifierEnum.ThirtyTwoBytes.valueOf();
    } else {
      throw new Error('Unsupported identifier length: ' + identifierLength);
    }
    // Buffer to hold the protocol, length of body, body, and identifierPadded
    const buffer = new Uint8Array(1 + 1 + bodyLength + identifierPaddedLength);
    buffer.set(protocolIdentifierByte, 0);
    buffer.set([bodyLength], 1);
    buffer.set(new TextEncoder().encode(body), 2);
    // add padded identifier
    if (identifierPaddedLength > 0) {
      const identifierArray = new Uint8Array(identifierPaddedLength);
      const encodedIdentifier = new TextEncoder()
        .encode(identifier)
        .subarray(0, identifierPaddedLength);
      identifierArray.set(encodedIdentifier);
      buffer.set(identifierArray, 2 + bodyLength);
    }
    return new ResourceLocator(buffer);
  }

  constructor(buff: Uint8Array) {
    // Protocol
    this.protocol = buff[ResourceLocator.PROTOCOL_OFFSET];
    // Length of body
    this.lengthOfBody = buff[ResourceLocator.LENGTH_OFFSET];
    // Body as utf8 string
    const decoder = new TextDecoder();
    this.body = decoder.decode(
      buff.subarray(ResourceLocator.BODY_OFFSET, ResourceLocator.BODY_OFFSET + this.lengthOfBody)
    );
    // identifier
    this.identifierType = ResourceLocatorIdentifierEnum.None
    const identifierTypeNibble = this.protocol & 0xf;
    if ((identifierTypeNibble & 0b0010) !== 0) {
      this.identifierType = ResourceLocatorIdentifierEnum.TwoBytes;
    } else if ((identifierTypeNibble & 0b0100) !== 0) {
      this.identifierType = ResourceLocatorIdentifierEnum.EightBytes;
    } else if ((identifierTypeNibble & 0b1000) !== 0) {
      this.identifierType = ResourceLocatorIdentifierEnum.ThirtyTwoBytes;
    }
    switch (this.identifierType) {
      case ResourceLocatorIdentifierEnum.None:
        // noop
        break;
      case ResourceLocatorIdentifierEnum.TwoBytes:
      case ResourceLocatorIdentifierEnum.EightBytes:
      case ResourceLocatorIdentifierEnum.ThirtyTwoBytes:
        this.identifier = decoder.decode(
          buff.subarray(
            ResourceLocator.BODY_OFFSET + this.lengthOfBody,
            ResourceLocator.BODY_OFFSET + this.lengthOfBody + this.identifierType.valueOf()
          )
        );
        break;
    }
    this.offset =
      ResourceLocator.PROTOCOL_LENGTH +
      ResourceLocator.LENGTH_LENGTH +
      this.lengthOfBody +
      this.identifierType.valueOf();
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
      this.identifier.length
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
    const buffer = new Uint8Array(2 + this.body.length + this.identifier.length);
    buffer.set([this.protocol], 0);
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
