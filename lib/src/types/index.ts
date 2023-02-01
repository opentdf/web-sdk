import PolicyTypeEnum from '../nanotdf/enum/PolicyTypeEnum.js';

export type InputSource =
  | ReadableStream<Uint8Array>
  | Uint8Array
  | string
  | ArrayBuffer
  | Promise<ReadableStream<Uint8Array>>;

type Header = {
  magicNumberVersion: string[];
  kas: {
    protocol: number;
    length: number;
    body: string;
  };
  eccBindingMode: {
    useECDSABinding: boolean;
    ephemeralCurveName: number;
  };
  symmetricPayloadConfig: {
    hasSignature: boolean;
    signatureCurveName: number;
    symmetricCipher: number;
  };
  ephemeralPublicKey: string[];
};

type HeaderPolicy = {
  type: PolicyTypeEnum;
  content: string[];
  binding: string[];
};

type RemotePolicy = {
  protocol: number;
  length: number;
  body: string;
};

export type PlainEmbeddedHeader = Header & {
  policy: HeaderPolicy;
};

export type EmbeddedHeader = Header & {
  policy: HeaderPolicy;
};

export type RemoteHeader = Header & {
  policy: {
    type: PolicyTypeEnum;
    remotePolicy: RemotePolicy;
    binding: string[];
  };
};
