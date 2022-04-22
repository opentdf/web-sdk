/**
 * Generic HTTP request interface used by AuthProvider implementers.
 */
class HttpRequest {
  headers: Record<string, string>;

  params: object;

  method: 'get' | 'head' | 'post' | 'put' | 'delete' | 'connect' | 'options' | 'trace' | 'patch';

  url: string;

  body?: unknown;

  constructor() {
    this.headers = {};
    this.params = {};
    this.method = 'post';
    this.url = null;
  }
}

export default HttpRequest;
