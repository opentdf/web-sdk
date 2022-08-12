import { Client as ClientTdf3 } from '../tdf3/src/client';
import { DecryptParamsBuilder, EncryptParamsBuilder } from '../tdf3/src/client/builders';
import { PlaintextStream } from '../tdf3/src/client/tdf-stream';
import { EncryptParams, DecryptParams } from '../tdf3/src/client/builders';
import { InputSource } from '../src/types';

interface FileClientConfig {
  clientId: string;
  organizationName: string;
  oidcOrigin: string;
  kasEndpoint: string;
  clientSecret?: string;
  oidcRefreshToken?: string;
}

function isNodeStream(source: InputSource): source is NodeJS.ReadableStream {
  return Object.prototype.hasOwnProperty.call(source, 'pipe');
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
    users: string[] = [],
    params?: EncryptParams
  ): Promise<PlaintextStream> {
    const encryptParams = new EncryptParamsBuilder().withOffline().withUsersWithAccess(users);

    if (params) {
      return await this.client.encrypt(params);
    }
    const result = FileClient.setSource(source, encryptParams);
    return await this.client.encrypt(<EncryptParams>result);
  }

  async decrypt(source: InputSource = '', params?: DecryptParams): Promise<PlaintextStream> {
    const decryptParams = new DecryptParamsBuilder();

    if (params) {
      return await this.client.decrypt(params);
    }
    const result = FileClient.setSource(source, decryptParams);
    return await this.client.decrypt(<DecryptParams>result);
  }
}
