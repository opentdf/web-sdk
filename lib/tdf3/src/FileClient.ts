import { createReadStream } from 'fs';
import { Readable } from 'stream';

import { Client as ClientTdf3 } from './client/index.js';
import {
  type DecryptParams,
  DecryptParamsBuilder,
  type EncryptParams,
  EncryptParamsBuilder,
} from './client/builders.js';
import { type InputSource } from '../../src/types/index.js';
import { type AuthProvider } from '../../src/auth/auth.js';
import { type AnyTdfStream } from './client/tdf-stream.js';

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
  client: ClientTdf3;

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
      let url;
      try {
        url = new URL(source);
        if (!['http', 'https'].includes(url.protocol)) {
          url = undefined;
        }
      } catch (_) {
        // Not a url
      }
      if (params instanceof EncryptParamsBuilder) {
        if (url) {
          const response = await fetch(url);
          if (!response.ok) {
            console.warn(
              `${response.status} Error while fetching [${url}]: [${response.statusText}]`
            );
            throw new Error(response.statusText);
          }
          if (!response.body) {
            throw new Error(`${response.status}: No body returned.`);
          }
          source = response.body;
        } else {
          source = Readable.toWeb(createReadStream(source)) as ReadableStream<Uint8Array>;
        }
        params.setStreamSource(source);
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
  ): Promise<AnyTdfStream | null> {
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
