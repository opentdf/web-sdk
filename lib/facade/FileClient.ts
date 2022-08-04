import { Client as ClientTdf3 } from '../tdf3/src/client';
import { DecryptParamsBuilder, EncryptParamsBuilder } from '../tdf3/src/client/builders';
import { PlaintextStream } from '../tdf3/src/client/tdf-stream';

interface FileClientConfig {
  clientId: string;
  organizationName: string;
  oidcOrigin: string;
  kasEndpoint: string;
  clientSecret?: string;
  oidcRefreshToken?: string;
}

export class FileClient {
  private client: ClientTdf3;

  constructor({
    clientId,
    clientSecret,
    oidcRefreshToken,
    organizationName,
    oidcOrigin,
    kasEndpoint,
  }: FileClientConfig) {
    this.client = new ClientTdf3({
      clientId,
      organizationName,
      clientSecret,
      oidcRefreshToken,
      kasEndpoint,
      oidcOrigin,
    });
  }

  private static setSource(
    source: ReadableStream | Buffer | string | ArrayBuffer,
    params: EncryptParamsBuilder | DecryptParamsBuilder
  ) {
    if (Object.prototype.hasOwnProperty.call(source, 'pipe') || source instanceof ReadableStream) {
      params.setStreamSource(source);
    }
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
    return params.build();
  }

  async encrypt(
    source: ReadableStream | Buffer | string | ArrayBuffer = '',
    users: string[] = [],
    params?: any
  ): Promise<PlaintextStream> {
    const encryptParams = new EncryptParamsBuilder().withOffline().withUsersWithAccess(users);

    if (params) {
      return await this.client.encrypt(params);
    }
    return await this.client.encrypt(FileClient.setSource(source, encryptParams));
  }

  async decrypt(
    source: ReadableStream | Buffer | string | ArrayBuffer = '',
    params?: any
  ): Promise<PlaintextStream> {
    const decryptParams = new DecryptParamsBuilder();

    if (params) {
      return await this.client.decrypt(params);
    }
    return await this.client.decrypt(FileClient.setSource(source, decryptParams));
  }
}
