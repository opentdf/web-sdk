import { open } from 'fs/promises';

import { Client as ClientTdf3 } from './client/index';
import { DecryptParamsBuilder, EncryptParamsBuilder } from './client/builders';
import { type Disposable } from './utils/using';
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

export class FileClient {
  dissems: string[] = [];
  dataAttributes: string[] = [];
  private client: ClientTdf3;

  constructor({
    clientId,
    clientSecret,
    oidcRefreshToken,
    oidcOrigin,
    kasEndpoint,
    authProvider,
  }: FileClientConfig) {
    this.client = new ClientTdf3({
      authProvider,
      clientId,
      clientSecret,
      oidcRefreshToken,
      kasEndpoint,
      oidcOrigin,
    });
  }

  private static setSource(
    source: InputSource,
    params: DecryptParamsBuilder
  ): Promise<DecryptParams & Disposable>;
  private static setSource(
    source: InputSource,
    params: EncryptParamsBuilder
  ): Promise<EncryptParams & Disposable>;
  private static async setSource(
    source: InputSource,
    params: DecryptParamsBuilder | EncryptParamsBuilder
  ): Promise<(EncryptParams | DecryptParams) & Disposable> {
    if (Buffer && Buffer.isBuffer(source)) {
      params.setBufferSource(source);
    }
    if (source instanceof ArrayBuffer) {
      params.setArrayBufferSource(source);
    }
    if (source instanceof Promise) {
      source = await source;
    }
    let dispose = undefined;
    if (typeof source === 'string' && params instanceof EncryptParamsBuilder) {
      const file = await open(source);
      source = file.readableWebStream();
      dispose = () => file.close().catch((e) => console.error(e));
    }
    if (source instanceof ReadableStream) {
      params.setStreamSource(source);
    }
    return { dispose, ...params.build() };
  }

  async encrypt(
    source: InputSource = '',
    users?: string[],
    params?: EncryptParams
  ): Promise<AnyTdfStream> {
    const encryptParams = new EncryptParamsBuilder()
      .withOffline()
      .withUsersWithAccess(users || this.dissems)
      .withAttributes(
        this.dataAttributes.map((attribute) => {
          return { attribute };
        })
      );

    if (params) {
      return await this.client.encrypt(params);
    }

    const result = await FileClient.setSource(source, encryptParams);
    return await this.client.encrypt(result);
  }

  async decrypt(source: InputSource = '', params?: DecryptParams): Promise<AnyTdfStream> {
    const decryptParams = new DecryptParamsBuilder();

    if (params) {
      return await this.client.decrypt(params);
    }
    const result = await FileClient.setSource(source, decryptParams);
    return await this.client.decrypt(result);
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
