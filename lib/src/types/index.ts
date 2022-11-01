import PolicyTypeEnum from '../nanotdf/enum/PolicyTypeEnum';

export type InputSource = ReadableStream | Buffer | string | ArrayBuffer | Promise<ReadableStream>;

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
