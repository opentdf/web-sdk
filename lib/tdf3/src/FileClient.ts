import { createReadStream } from 'fs';
import { Readable } from 'stream';
import axios from 'axios';
import { Client as ClientTdf3 } from './client/index';
import { DecryptParamsBuilder, EncryptParamsBuilder } from './client/builders';
import { type EncryptParams, type DecryptParams } from './client/builders';
import { type InputSource } from '../../src/types';
import { type AuthProvider } from '../../src/auth/auth';
import { AnyTdfStream } from './client/tdf-stream';

interface FileClientConfig {
  clientId?: string;
  oidcOrigin?: string;
  clientSecret?: string;
  oidcRefreshToken?: string;

  authProvider?: AuthProvider;

  kasEndpoint?: string;
}

function isClientTdf3(c: unknown): c is ClientTdf3 {
  if (typeof c !== 'object') {
    return false;
  }
  return !!((c as ClientTdf3).encrypt && (c as ClientTdf3).decrypt);
}

export class FileClient {
  dissems: string[] = [];
  dataAttributes: string[] = [];
  private client: ClientTdf3;

  constructor(opts: FileClientConfig | ClientTdf3) {
    // I'm using a duck type check here to make it easier to mock.
    if (isClientTdf3(opts)) {
      this.client = opts;
    } else {
      this.client = new ClientTdf3(opts);
    }
  }

  private static setSource(source: InputSource, params: DecryptParamsBuilder): Promise<void>;
  private static setSource(source: InputSource, params: EncryptParamsBuilder): Promise<void>;
  private static async setSource(
    source: InputSource,
    params: DecryptParamsBuilder | EncryptParamsBuilder
  ): Promise<void> {
    if (source instanceof Promise) {
      source = await source;
    }
    if (Buffer && Buffer.isBuffer(source)) {
      params.setBufferSource(source);
      return;
    }
    if (source instanceof ArrayBuffer) {
      params.setArrayBufferSource(source);
      return;
    }
    if (typeof source === 'string') {
      let url: URL | undefined;
      try {
        url = new URL(source);
        if (!['http', 'https'].includes(url.protocol)) {
          url = undefined;
        }
      } catch (_) {
        // Not a url
      }
      if (params instanceof EncryptParamsBuilder) {
        if (url && url.href) {
          try {
            const response = await axios.get(url.href, { responseType: 'stream' });
            if (!response.data) {
              throw new Error(`${response.status}: No body returned.`);
            }
            source = Readable.toWeb(response.data);
          } catch (e) {
            if (e.response) { // if axios error
              console.warn(
                `${e.response.status} Error while fetching [${url.href}]: [${e.response.statusText}]`
              );
              throw new Error(e.response.statusText);
            }
            if (e.message) {
              throw new Error(e.message);
            }
          }
        } else {
          source = Readable.toWeb(createReadStream(source));
        }
        params.setStreamSource(source as ReadableStream<Uint8Array>);
      } else {
        // params instanceof DecryptParamsBuilder
        if (url) {
          params.setUrlSource(source);
        } else {
          params.setFileSource(source);
        }
      }
    }
  }

  async encrypt(
    source: InputSource = '',
    users?: string[],
    params?: EncryptParams
  ): Promise<AnyTdfStream> {
    const defaultParams =
      params ||
      new EncryptParamsBuilder()
        .withOffline()
        .withUsersWithAccess(this.dissems)
        .withAttributes(
          this.dataAttributes.map((attribute) => {
            return { attribute };
          })
        )
        .build();
    if (users) {
      // XXX Should this append to existing scope or replace it?
      defaultParams.scope.dissem = [...users];
    }
    const paramsBuilder = new EncryptParamsBuilder(defaultParams);
    await FileClient.setSource(source, paramsBuilder);
    return await this.client.encrypt(paramsBuilder.build());
  }

  async decrypt(source: InputSource = '', params?: DecryptParams): Promise<AnyTdfStream> {
    const decryptParams = new DecryptParamsBuilder(params);
    if (source) {
      await FileClient.setSource(source, decryptParams);
    }
    return await this.client.decrypt(decryptParams.build());
  }

  /**
   * Add attribute to the TDF file/data
   *
   * @param attribute The attribute that decides the access control of the TDF.
   */
  addAttribute(attribute: string): void {
    this.dataAttributes.push(attribute);
  }
}
