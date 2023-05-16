import { VirtruS3Config } from '../../client/builders.js';
import { PutObjectCommand } from './PutObjectCommand.js';
import { clientType, version } from '../../../../src/version.js';
import { Sha256 } from './sha256.js';
import { v4 } from 'uuid';
import { SignatureV4 } from './SigantureV4.js';
import { type AuthScheme, type HttpRequest} from '@aws-sdk/types';


export class S3Client {
  config: VirtruS3Config;
  attempt: number;

  constructor(params : VirtruS3Config) {
    this.config = params;
    this.attempt = 0;
  }

  signer() {
    const authScheme: AuthScheme = {
      signingName: 's3',
      name: "sigv4",
      signingRegion: String(this.config.region),
      // @ts-ignore
      disableDoubleEncoding: true,
      properties: {},
    };
    const signingRegion = authScheme.signingRegion;

    this.config.signingRegion = this.config.signingRegion || signingRegion;

    const params = {
      ...this.config,
      credentials: this.config.credentials,
      region: this.config.signingRegion,
      service: authScheme.signingName,
      sha256: Sha256,
      uriEscapePath: this.config.signingEscapePath,
    };
    this.config.endpoint;
    return new SignatureV4(params);
  };


  private _getUserAgent(headers: Record<string, string>) {
    const key = window ? 'x-amz-user-agent' : 'user-agent';
    headers[key] = `${clientType}/${version}`
  }

  async send(putObject: PutObjectCommand) {
    // wrap it in while

    const endpointObj = new URL(String(this.config.endpoint));
    const hostname = `${endpointObj.protocol}//${this.config.Bucket}.${endpointObj.hostname}`

    const request: HttpRequest = {
      method: 'PUT',
      headers: {
        host: hostname,
        'content-type': 'application/octet-stream',
      },
      protocol: endpointObj.protocol,
      hostname,
      path: '/' + putObject.input.Key,
      query: {'x-id': 'PutObject'},
    }

    console.log('putObject')
    console.log(putObject)
    if (ArrayBuffer.isView(putObject.input.Body)){
      console.log('String(putObject.input.Body.byteLength)');
      console.log(String(putObject.input.Body.byteLength));
      request.headers['content-length'] = String(putObject.input.Body.byteLength);
    }

    request.headers['amz-sdk-invocation-id'] = v4();
    this._getUserAgent(request.headers);

    const defaultMaxAttempts = 3

    request.headers['amz-sdk-request'] = `attempt=${this.attempt + 1}; max=${this.config.maxAttempts || defaultMaxAttempts}`;
    request.body = putObject.input.Body

    const signer = this.signer();

    // signingDate = new Date(),
    //   signableHeaders,
    //   unsignableHeaders,
    //   signingRegion,
    //   signingService,
    console.log('this.config.signingRegion')
    console.log(this.config.signingRegion)
    const requestSigned = await signer.signRequest(request, {
        signingRegion: this.config.signingRegion,
        signingService: 's3',
      });
    return this.handle(requestSigned);
  }

  async handle(request: HttpRequest) {
    let path = request.path;
    if (request.query) {
      request.query = Array.isArray(request.query) ? Object.fromEntries(request.query) : request.query
      const queryString =  new URLSearchParams(request.query as Record<string, string>).toString();
      if (queryString) {
        path += `?${queryString}`;
      }
    }
    const { port, method } = request;
    console.log(request)
    const url = `${request.hostname}${port ? `:${port}` : ""}${path}`;
    const body = method === "GET" || method === "HEAD" ? undefined : request.body;
    const requestOptions = {
      body,
      headers: new Headers(request.headers),
      method: method,
    };
    const fetchRequest = new Request(url, requestOptions);
    console.log(fetchRequest);

    // @ts-ignore
    return fetch(fetchRequest).then((response) => {
      const fetchHeaders = response.headers;
      const transformedHeaders = {};
      for (const [key, value] of fetchHeaders.entries()) {
        // @ts-ignore
        transformedHeaders[key] = value;
      }
      const hasReadableStream = response.body !== undefined;
      if (!hasReadableStream) {
        return response.blob().then((body) => ({
          response: {
            headers: transformedHeaders,
            statusCode: response.status,
            body,
          },
        }));
      }
      return {
        response: {
          headers: transformedHeaders,
          statusCode: response.status,
          body: response.body,
        },
      };
    });
  }
}