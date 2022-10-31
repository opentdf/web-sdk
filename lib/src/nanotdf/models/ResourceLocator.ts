import ProtocolEnum from '../enum/ProtocolEnum.js';

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
 *
 * @link https://github.com/virtru/nanotdf/blob/master/spec/index.md#3312-kas
 * @link https://github.com/virtru/nanotdf/blob/master/spec/index.md#341-resource-locator
 */
export default class ResourceLocator {
  readonly protocol: ProtocolEnum;
  readonly lengthOfBody: number;
  readonly body: string;
  readonly offset: number = 0;

  static readonly PROTOCOL_OFFSET = 0;
  static readonly PROTOCOL_LENGTH = 1;
  static readonly LENGTH_OFFSET = 1;
  static readonly LENGTH_LENGTH = 1;
  static readonly BODY_OFFSET = 2;

  static parse(url: string): ResourceLocator {
    const [protocol, body] = url.split('://');

    // Buffer to hold the protocol, length of body, body
    const buffer = new Uint8Array(1 + 1 + body.length);
    buffer.set([body.length], 1);
    buffer.set(new TextEncoder().encode(body), 2);

    if (protocol.toLowerCase() == 'http') {
      buffer.set([ProtocolEnum.Http], 0);
    } else if (protocol.toLowerCase() == 'https') {
      buffer.set([ProtocolEnum.Https], 0);
    } else {
      throw new Error('Resource locator protocol is not supported.');
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
    this.offset =
      ResourceLocator.PROTOCOL_LENGTH + ResourceLocator.LENGTH_LENGTH + this.lengthOfBody;
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
      this.body.length
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
    const buffer = new Uint8Array(2 + this.body.length);
    buffer.set([this.protocol], 0);
    buffer.set([this.lengthOfBody], 1);
    buffer.set(new TextEncoder().encode(this.body), 2);

    return buffer;
  }

  /**
   * Get URL
   *
   * Construct URL from ResourceLocator or throw error
   */
  getUrl(): string | never {
    let protocol;
    if (this.protocol === ProtocolEnum.Http) {
      protocol = 'http';
    } else if (this.protocol === ProtocolEnum.Https) {
      protocol = 'https';
    } else {
      throw new Error(`Cannot create URL from protocol, ${ProtocolEnum[this.protocol]}`);
    }

    return `${protocol}://${this.body}`;
  }
}
