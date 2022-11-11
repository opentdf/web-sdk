import { createReadStream } from 'fs';
import { Readable } from 'stream';

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
  ): Promise<DecryptParams>;
  private static setSource(
    source: InputSource,
    params: EncryptParamsBuilder
  ): Promise<EncryptParams>;
  private static async setSource(
    source: InputSource,
    params: DecryptParamsBuilder | EncryptParamsBuilder
  ): Promise<void> {
    if (Buffer && Buffer.isBuffer(source)) {
      params.setBufferSource(source);
    }
    if (source instanceof ArrayBuffer) {
      params.setArrayBufferSource(source);
    }
    if (source instanceof Promise) {
      source = await source;
    }
    if (typeof source === 'string' && params instanceof EncryptParamsBuilder) {
      source = Readable.toWeb(createReadStream(source));
    }
    if (source instanceof ReadableStream) {
      params.setStreamSource(source);
    }
  }

  async encrypt(
    source: InputSource = '',
    users?: string[],
    params?: EncryptParams
  ): Promise<AnyTdfStream> {
    const encryptParams = new EncryptParamsBuilder(params)
      .withOffline()
      .withUsersWithAccess(users || this.dissems)
      .withAttributes(
        this.dataAttributes.map((attribute) => {
          return { attribute };
        })
      );
    if (source) {
      await FileClient.setSource(source, encryptParams);
    }
    return await this.client.encrypt(encryptParams.build());
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
