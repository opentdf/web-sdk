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
    const [protocol, body] = url.split('://');

    // Validate and set protocol identifier byte
    const protocolIdentifierByte = new Uint8Array(1);
    switch (protocol.toLowerCase()) {
      case 'http':
        protocolIdentifierByte[0] = 0x00;
        break;
      case 'https':
        protocolIdentifierByte[0] = 0x01;
        break;
      default:
        throw new Error('resource locator protocol unsupported');
    }

    // Set identifier padded length and protocol identifier byte
    const identifierPaddedLength = (() => {
      switch (identifier.length) {
        case 0:
          protocolIdentifierByte[0] |= ResourceLocator.IDENTIFIER_0_BYTE;
          return ResourceLocatorIdentifierEnum.None.valueOf();
        case 2:
          protocolIdentifierByte[0] |= ResourceLocator.IDENTIFIER_2_BYTE;
          return ResourceLocatorIdentifierEnum.TwoBytes.valueOf();
        case 8:
          protocolIdentifierByte[0] |= ResourceLocator.IDENTIFIER_8_BYTE;
          return ResourceLocatorIdentifierEnum.EightBytes.valueOf();
        case 32:
          protocolIdentifierByte[0] |= ResourceLocator.IDENTIFIER_32_BYTE;
          return ResourceLocatorIdentifierEnum.ThirtyTwoBytes.valueOf();
        default:
          throw new Error(`Unsupported identifier length: ${identifier.length}`);
      }
    })();

    // Create buffer to hold protocol, body length, body, and identifier
    const bodyBytes = new TextEncoder().encode(body);
    const buffer = new Uint8Array(1 + 1 + bodyBytes.length + identifierPaddedLength);

    // Set the protocol, body length, body and identifier into buffer
    buffer.set(protocolIdentifierByte, 0);
    buffer.set([bodyBytes.length], 1);
    buffer.set(bodyBytes, 2);

    if (identifierPaddedLength > 0) {
      const identifierBytes = new TextEncoder()
        .encode(identifier)
        .subarray(0, identifierPaddedLength);
      buffer.set(identifierBytes, 2 + bodyBytes.length);
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
    const identifierTypeNibble = this.protocol;
    if (identifierTypeNibble === ResourceLocator.IDENTIFIER_2_BYTE) {
      this.identifierType = ResourceLocatorIdentifierEnum.TwoBytes;
    } else if (identifierTypeNibble === ResourceLocator.IDENTIFIER_8_BYTE) {
      this.identifierType = ResourceLocatorIdentifierEnum.EightBytes;
    } else if (identifierTypeNibble === ResourceLocator.IDENTIFIER_32_BYTE) {
      this.identifierType = ResourceLocatorIdentifierEnum.ThirtyTwoBytes;
    }
    switch (this.identifierType) {
      case ResourceLocatorIdentifierEnum.None:
        // noop
        break;
      case ResourceLocatorIdentifierEnum.TwoBytes:
      case ResourceLocatorIdentifierEnum.EightBytes:
      case ResourceLocatorIdentifierEnum.ThirtyTwoBytes:
        const start = ResourceLocator.BODY_OFFSET + this.lengthOfBody;
        const end = start + this.identifierType.valueOf();
        const subarray = buff.subarray(start, end);
        // Remove padding (assuming the padding is null bytes, 0x00)
        const trimmedSubarray = subarray.filter((byte) => byte !== 0x00);
        this.identifier = decoder.decode(trimmedSubarray);
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
      this.identifierType.valueOf()
    );
  }

  get url(): string | never {
    switch (this.protocol & 0xf) {
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
    const buffer = new Uint8Array(2 + this.body.length + this.identifierType.valueOf());
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
