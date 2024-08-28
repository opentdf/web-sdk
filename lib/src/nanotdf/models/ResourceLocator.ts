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

  constructor(url: string, identifier?: string) {
    const [protocol, body] = url.split('://');

    // Validate and set protocol identifier byte
    switch (protocol.toLowerCase()) {
      case 'http':
        this.protocol = ProtocolEnum.Http;
        break;
      case 'https':
        this.protocol = ProtocolEnum.Https;
        break;
      default:
        throw new Error(`resource locator protocol [${protocol}] unsupported`);
    }
    this.body = body;

    // Set identifier padded length and protocol identifier byte
    this.identifierType = (() => {
      if (!identifier) {
        return ResourceLocatorIdentifierEnum.None;
      }
      const identifierLength = new TextEncoder().encode(identifier).length;
      if (identifierLength <= 2) {
        return ResourceLocatorIdentifierEnum.TwoBytes;
      } else if (identifierLength <= 8) {
        return ResourceLocatorIdentifierEnum.EightBytes;
      } else if (identifierLength <= 32) {
        return ResourceLocatorIdentifierEnum.ThirtyTwoBytes;
      }
      throw new Error(`Unsupported identifier length: ${identifier.length}`);
    })();
    if (identifier) {
      this.identifier = identifier;
    }

    // Create buffer to hold protocol, body length, body, and identifier
    this.lengthOfBody = new TextEncoder().encode(body).length;
    const identifierLength = this.identifierType.valueOf();
    this.offset = ResourceLocator.BODY_OFFSET + this.lengthOfBody + identifierLength;
  }

  static parse(buff: Uint8Array) {
    // Protocol
    const protocolAndIdentifierType = buff[ResourceLocator.PROTOCOL_OFFSET];
    // Length of body
    const lengthOfBody = buff[ResourceLocator.LENGTH_OFFSET];
    // Body as utf8 string
    const decoder = new TextDecoder();
    const body = decoder.decode(
      buff.subarray(ResourceLocator.BODY_OFFSET, ResourceLocator.BODY_OFFSET + lengthOfBody)
    );
    const protocol = protocolAndIdentifierType & 0xf;
    let url = '';
    switch (protocol) {
      case ProtocolEnum.Http:
        url = 'http://' + body;
        break;
      case ProtocolEnum.Https:
        url = 'https://' + body;
        break;
      default:
        throw new Error(`unsupported protocol type [${protocol}]`);
    }
    // identifier
    const identifierTypeNibble = protocolAndIdentifierType & 0xf0;
    let identifierType = ResourceLocatorIdentifierEnum.None;
    if (identifierTypeNibble === ResourceLocator.IDENTIFIER_2_BYTE) {
      identifierType = ResourceLocatorIdentifierEnum.TwoBytes;
    } else if (identifierTypeNibble === ResourceLocator.IDENTIFIER_8_BYTE) {
      identifierType = ResourceLocatorIdentifierEnum.EightBytes;
    } else if (identifierTypeNibble === ResourceLocator.IDENTIFIER_32_BYTE) {
      identifierType = ResourceLocatorIdentifierEnum.ThirtyTwoBytes;
    }

    let identifier: string | undefined = undefined;

    switch (identifierType) {
      case ResourceLocatorIdentifierEnum.None:
        // noop
        break;
      case ResourceLocatorIdentifierEnum.TwoBytes:
      case ResourceLocatorIdentifierEnum.EightBytes:
      case ResourceLocatorIdentifierEnum.ThirtyTwoBytes:
        const kidStart = ResourceLocator.BODY_OFFSET + lengthOfBody;
        const kidEnd = kidStart + identifierType.valueOf();
        const kidSubarray = buff.subarray(kidStart, kidEnd);
        // Remove padding (assuming the padding is null bytes, 0x00)
        const zeroIndex = kidSubarray.indexOf(0);
        if (zeroIndex >= 0) {
          const trimmedSubarray = kidSubarray.subarray(0, zeroIndex);
          identifier = decoder.decode(trimmedSubarray);
        } else {
          identifier = decoder.decode(kidSubarray);
        }
        break;
    }
    return new ResourceLocator(url, identifier);
  }

  /**
   * Length
   *
   * @returns { number } Length of resource locator
   */
  get length(): number {
    return this.offset;
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
    const buffer = new Uint8Array(
      ResourceLocator.BODY_OFFSET + this.body.length + this.identifierType
    );
    let idTypeNibble = 0;
    switch (this.identifierType) {
      case ResourceLocatorIdentifierEnum.TwoBytes:
        idTypeNibble = ResourceLocator.IDENTIFIER_2_BYTE;
        break;
      case ResourceLocatorIdentifierEnum.EightBytes:
        idTypeNibble = ResourceLocator.IDENTIFIER_8_BYTE;
        break;
      case ResourceLocatorIdentifierEnum.ThirtyTwoBytes:
        idTypeNibble = ResourceLocator.IDENTIFIER_32_BYTE;
        break;
    }
    buffer.set([this.protocol | idTypeNibble], ResourceLocator.PROTOCOL_OFFSET);
    buffer.set([this.lengthOfBody], ResourceLocator.LENGTH_OFFSET);
    buffer.set(new TextEncoder().encode(this.body), ResourceLocator.BODY_OFFSET);
    if (this.identifier) {
      buffer.set(
        new TextEncoder().encode(this.identifier),
        ResourceLocator.BODY_OFFSET + this.body.length
      );
    }
    return buffer;
  }

  /**
   * Get Identifier
   *
   * Returns the identifier of the ResourceLocator or an empty string if no identifier is present.
   * @returns { string } Identifier of the resource locator.
   */
  get kid(): string {
    return this.identifier || '';
  }
}
