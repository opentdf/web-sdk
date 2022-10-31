import { Client as ClientTdf3 } from './client/index';
import { DecryptParamsBuilder, EncryptParamsBuilder } from './client/builders';
import { type AnyTdfStream } from './client/tdf-stream';
import { type EncryptParams, type DecryptParams } from './client/builders';
import { type InputSource } from '../../src/types';
import { type AuthProvider } from '../../src/auth/auth';

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
    params: EncryptParamsBuilder | DecryptParamsBuilder
  ) {
    if (Buffer && Buffer.isBuffer(source)) {
      params.setBufferSource(source);
    }
    if (typeof source === 'string') {
      // there is not point to used tdf3.js withStringSource, after merging we have nanoTdf for that
      params.setFileSource(source);
    }
    if (source instanceof ArrayBuffer) {
      params.setArrayBufferSource(source);
    }

    if (isNodeStream(source) || source instanceof ReadableStream) {
      params.setStreamSource(source);
    }
    return params.build();
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
    const result = FileClient.setSource(source, encryptParams);
    return await this.client.encrypt(<EncryptParams>result);
  }

  async decrypt(source: InputSource = '', params?: DecryptParams): Promise<AnyTdfStream> {
    const decryptParams = new DecryptParamsBuilder();

    if (params) {
      return await this.client.decrypt(params);
    }
    const result = FileClient.setSource(source, decryptParams);
    return await this.client.decrypt(<DecryptParams>result);
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
