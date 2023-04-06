import axios, { type AxiosResponse, type RawAxiosRequestConfig } from 'axios';

import { AppIdAuthProvider, HttpRequest } from './auth.js';

const { request } = axios;

// Required `any` below is to match type from axios library.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type RequestFunctor = <T = any, R = AxiosResponse<T>>(config: RawAxiosRequestConfig) => Promise<R>;

/**
 * Client for EAS interaction, specifically fetching entity object.
 */
class Eas {
  authProvider: AppIdAuthProvider;

  endpoint: string;

  requestFunctor: RequestFunctor;

  /**
   * Create an object for accessing an Entity Attribute Service.
   * @param {object} config - options to  configure this EAS accessor
   * @param {AuthProvider|function} config.authProvider - interceptor for `http-request.Request` object manipulation
   * @param {string} config.endpoint - the URI to connect to
   * @param {function} [config.requestFunctor=request] - http request async function object
   */
  constructor({
    authProvider,
    endpoint,
    requestFunctor,
  }: {
    authProvider: AppIdAuthProvider;
    endpoint: string;
    requestFunctor?: RequestFunctor;
  }) {
    this.authProvider = authProvider;
    this.endpoint = endpoint;
    this.requestFunctor = requestFunctor || request;
  }

  /**
   * Request an entity object for the current user.
   * @param {object} config - options for the request
   * @param {string} config.publicKey - String encoded public key from the keypair to be used with any subsequent requests refering to the returned EO
   * @param {object} [config.etc] - additional parameters to be passed to the EAS entity-object endpoint
   */
  async fetchEntityObject({ publicKey, ...etc }: { publicKey: string }) {
    // Create a skeleton http request for EAS.
    const incredibleHttpReq: HttpRequest = {
      url: this.endpoint,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      params: {
        format: 'jwt'
      },
      body: { publicKey, ...etc },
    };

    // Delegate modifications to the auth provider.
    // TODO: Handle various exception cases from interface docs.
    const httpReq = await this.authProvider.withCreds(incredibleHttpReq);

    // Execute the http request using axios.
    const axiosParams: RawAxiosRequestConfig = {
      method: httpReq.method,
      headers: httpReq.headers,
      url: httpReq.url,
      params: undefined,
      data: undefined,
    };
    // Allow the authProvider to change the method.
    if (httpReq.method === 'POST' || httpReq.method === 'PATCH' || httpReq.method === 'PUT') {
      axiosParams.data = httpReq.body;
    } else {
      axiosParams.params = httpReq.body;
    }
    return (await this.requestFunctor(axiosParams)).data;
  }
}

export default Eas;
