export type AlgorithmUrn =
  | 'http://www.w3.org/2001/04/xmlenc#aes256-cbc'
  | 'http://www.w3.org/2009/xmlenc11#aes256-gcm';
export type AlgorithmName = 'AES_256_CBC' | 'AES_256_GCM';

export const Algorithms: Record<AlgorithmName, AlgorithmUrn> = {
  AES_256_CBC: 'http://www.w3.org/2001/04/xmlenc#aes256-cbc',
  AES_256_GCM: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
};
