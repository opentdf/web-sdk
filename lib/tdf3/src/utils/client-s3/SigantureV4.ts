import {
  AwsCredentialIdentity,
  DateInput,
  HashConstructor,
  HeaderBag,
  HttpRequest,
  Provider,
  RequestSigningArguments,
} from "@aws-sdk/types";
import { toHex } from "./hexCoding.js";

import {
  ALGORITHM_IDENTIFIER,
  AMZ_DATE_HEADER,
  AUTH_HEADER,
  SHA256_HEADER,
  TOKEN_HEADER,
} from "./constants.js";
import { createScope, getSigningKey } from "./credentialDerivation.js";
import { getCanonicalHeaders } from "./getCanonicalHeaders.js";
import { getCanonicalQuery } from "./getCanonicalQuery.js";
import { getPayloadHash } from "./getPayloadHash.js";
import { hasHeader } from "./headerUtil.js";
import { prepareRequest } from "./prepareRequest.js";
import { iso8601 } from "./utilDate.js";
import { toUint8Array } from "./utils.js";

export const normalizeProvider = <T>(input: T | Provider<T>): Provider<T> => {
  if (typeof input === "function") return input as Provider<T>;
  const promisified = Promise.resolve(input);
  return () => promisified;
};


export interface SignatureV4Init {
  /**
   * The service signing name.
   */
  service: string;

  /**
   * The region name or a function that returns a promise that will be
   * resolved with the region name.
   */
  region: string | Provider<string>;

  /**
   * The credentials with which the request should be signed or a function
   * that returns a promise that will be resolved with credentials.
   */
  credentials: AwsCredentialIdentity | Provider<AwsCredentialIdentity> | undefined;

  /**
   * A constructor function for a hash object that will calculate SHA-256 HMAC
   * checksums.
   */
  sha256?: HashConstructor;

  /**
   * Whether to uri-escape the request URI path as part of computing the
   * canonical request string. This is required for every AWS service, except
   * Amazon S3, as of late 2017.
   *
   * @default [true]
   */
  uriEscapePath?: boolean;

  /**
   * Whether to calculate a checksum of the request body and include it as
   * either a request header (when signing) or as a query string parameter
   * (when presigning). This is required for AWS Glacier and Amazon S3 and optional for
   * every other AWS service as of late 2017.
   *
   * @default [true]
   */
  applyChecksum?: boolean;
}

export interface SignatureV4CryptoInit {
  sha256: HashConstructor;
}

export class SignatureV4 {
  private readonly service: string;
  private readonly regionProvider: Provider<string>;
  private readonly credentialProvider: Provider<AwsCredentialIdentity>;
  private readonly sha256: HashConstructor;
  private readonly uriEscapePath: boolean;
  private readonly applyChecksum?: boolean;

  constructor({
    applyChecksum = true,
    credentials,
    region,
    service,
    sha256,
    uriEscapePath = true,
  }: SignatureV4Init & SignatureV4CryptoInit) {
    this.service = service;
    this.sha256 = sha256;
    this.uriEscapePath = uriEscapePath;
    // default to true if applyChecksum isn't set
    this.applyChecksum = typeof applyChecksum === "boolean" ? applyChecksum : true;
    this.regionProvider = normalizeProvider(region);
    if (!credentials) {
      throw new Error('Credentials should be passed')
    }
    this.credentialProvider = normalizeProvider(credentials);
  }

  async signRequest(
    requestToSign: HttpRequest,
    {
      signingDate = new Date(),
      signableHeaders,
      unsignableHeaders,
      signingRegion,
      signingService,
    }: RequestSigningArguments = {}
  ): Promise<HttpRequest> {
    const credentials = await this.credentialProvider();
    this.validateResolvedCredentials(credentials);
    const region = signingRegion ?? (await this.regionProvider());
    const request = prepareRequest(requestToSign);
    const { longDate, shortDate } = formatDate(signingDate);
    const scope = createScope(shortDate, region, signingService ?? this.service);

    request.headers[AMZ_DATE_HEADER] = longDate;
    if (credentials.sessionToken) {
      request.headers[TOKEN_HEADER] = credentials.sessionToken;
    }

    const payloadHash = await getPayloadHash(request, this.sha256);
    if (!hasHeader(SHA256_HEADER, request.headers) && this.applyChecksum) {
      request.headers[SHA256_HEADER] = payloadHash;
    }

    const canonicalHeaders = getCanonicalHeaders(request, unsignableHeaders, signableHeaders);
    const signature = await this.getSignature(
      longDate,
      scope,
      this.getSigningKey(credentials, region, shortDate, signingService),
      this.createCanonicalRequest(request, canonicalHeaders, payloadHash)
    );

    request.headers[AUTH_HEADER] =
      `${ALGORITHM_IDENTIFIER} ` +
      `Credential=${credentials.accessKeyId}/${scope}, ` +
      `SignedHeaders=${getCanonicalHeaderList(canonicalHeaders)}, ` +
      `Signature=${signature}`;

    return request;
  }

  private createCanonicalRequest(request: HttpRequest, canonicalHeaders: HeaderBag, payloadHash: string): string {
    const sortedHeaders = Object.keys(canonicalHeaders).sort();
    return `${request.method}
${this.getCanonicalPath(request)}
${getCanonicalQuery(request)}
${sortedHeaders.map((name) => `${name}:${canonicalHeaders[name]}`).join("\n")}
${sortedHeaders.join(";")}
${payloadHash}`;
  }

  private async createStringToSign(
    longDate: string,
    credentialScope: string,
    canonicalRequest: string
  ): Promise<string> {
    const hash = new this.sha256();
    hash.update(toUint8Array(canonicalRequest));
    const hashedRequest = await hash.digest();

    return `${ALGORITHM_IDENTIFIER}
${longDate}
${credentialScope}
${toHex(hashedRequest)}`;
  }

  private getCanonicalPath({ path }: HttpRequest): string {
    if (this.uriEscapePath) {
      // Non-S3 services, we normalize the path and then double URI encode it.
      // Ref: "Remove Dot Segments" https://datatracker.ietf.org/doc/html/rfc3986#section-5.2.4
      const normalizedPathSegments = [];
      for (const pathSegment of path.split("/")) {
        if (pathSegment?.length === 0) continue;
        if (pathSegment === ".") continue;
        if (pathSegment === "..") {
          normalizedPathSegments.pop();
        } else {
          normalizedPathSegments.push(pathSegment);
        }
      }
      // Joining by single slashes to remove consecutive slashes.
      const normalizedPath = `${path?.startsWith("/") ? "/" : ""}${normalizedPathSegments.join("/")}${
        normalizedPathSegments.length > 0 && path?.endsWith("/") ? "/" : ""
      }`;

      const doubleEncoded = encodeURIComponent(normalizedPath);
      return doubleEncoded.replace(/%2F/g, "/");
    }

    // For S3, we shouldn't normalize the path. For example, object name
    // my-object//example//photo.user should not be normalized to
    // my-object/example/photo.user
    return path;
  }

  private async getSignature(
    longDate: string,
    credentialScope: string,
    keyPromise: Promise<Uint8Array>,
    canonicalRequest: string
  ): Promise<string> {
    const stringToSign = await this.createStringToSign(longDate, credentialScope, canonicalRequest);

    const hash = new this.sha256(await keyPromise);
    hash.update(toUint8Array(stringToSign));
    return toHex(await hash.digest());
  }

  private getSigningKey(
    credentials: AwsCredentialIdentity,
    region: string,
    shortDate: string,
    service?: string
  ): Promise<Uint8Array> {
    return getSigningKey(this.sha256, credentials, shortDate, region, service || this.service);
  }

  private validateResolvedCredentials(credentials: unknown) {
    if (
      typeof credentials !== "object" ||
      // @ts-expect-error: Property 'accessKeyId' does not exist on type 'object'.ts(2339)
      typeof credentials.accessKeyId !== "string" ||
      // @ts-expect-error: Property 'secretAccessKey' does not exist on type 'object'.ts(2339)
      typeof credentials.secretAccessKey !== "string"
    ) {
      throw new Error("Resolved credential object is not valid");
    }
  }
}

const formatDate = (now: DateInput): { longDate: string; shortDate: string } => {
  const longDate = iso8601(now).replace(/[\-:]/g, "");
  return {
    longDate,
    shortDate: longDate.slice(0, 8),
  };
};

const getCanonicalHeaderList = (headers: object): string => Object.keys(headers).sort().join(";");