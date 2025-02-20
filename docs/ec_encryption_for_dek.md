# EC Encryption for DEK in ECWrapped KAO

## Overview

In our system,
we use Elliptic Curve (EC) encryption to securely encode the Data Encryption Key (DEK) within ECWrapped Key Access Objects (KAO).
This document explains the process and the underlying mechanisms involved.

## Key Components

1. **Elliptic Curve Cryptography (ECC)**:
A public key cryptography approach based on the algebraic structure of elliptic curves over finite fields.
2. **Data Encryption Key (DEK)**:
A symmetric key used to encrypt the actual data.
3. **Key Access Object (KAO)**:
An object that stores information about how the DEK is stored and accessed.
4. **Ephemeral Key Pair**:
A temporary key pair generated for each encryption session.
5. **Key Agreement**:
A process to derive a shared secret between two parties using their private and public keys.

## Process

### 1. Initialization

When an ECWrapped KAO is created,
an ephemeral key pair is generated using the P-256 curve:

```typescript
const ephemera = crypto.subtle.generateKey(
  {
    name: 'ECDH',
    namedCurve: 'P-256',
  },
  /* extractable: */ false,
  /* keyUsages: */ ['deriveBits', 'deriveKey']
);
```

### 2. Key Agreement

To securely transmit the DEK,
a key agreement is performed between the ephemeral private key and the recipient's public key.
This derives a shared secret (KEK - Key Encryption Key):

```typescript
const kasPublicKey: CryptoKey = /* Fetch or otherwise load known KAS public key value */;
const sharedSecret = await crypto.subtle.deriveBits(
    {
        name: 'ECDH',
        public: kasPublicKey,
    },
    ephemera.privateKey,
    256
);
const ikm = await crypto.subtle.importKey(
    'raw',
    sharedSecret,
    {
        name: 'HKDF',
    },
    false,
    ['deriveKey']
);
const kek = await crypto.subtle.deriveKey(
    {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new TextEncoder().encode('salt'),
    },
    ikm,
    {
        name: 'AES-GCM',
        length: 256,
    },
    false,
    ['encrypt', 'decrypt']
);
```

### 3. Encryption

The DEK is then encrypted using the derived KEK with AES-GCM algorithm.
A 12-byte initialization vector (IV) is also generated for this encryption.

```typescript
const iv = generateRandomNumber(12);
const cek = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, kek, dek);
const entityWrappedKey = new Uint8Array(iv.length + cek.byteLength);
entityWrappedKey.set(iv);
entityWrappedKey.set(new Uint8Array(cek), iv.length);
```

### 4. Storing in KAO

The encrypted DEK (entityWrappedKey) along with other metadata is stored in the KAO:

```typescript
const ephemeralPublicKeyPEM = await cryptoPublicToPem(ek.publicKey);
const kao: KeyAccessObject = {
  type: 'ec-wrapped',
  url: this.url,
  protocol: 'kas',
  wrappedKey: base64.encodeArrayBuffer(entityWrappedKey),
  encryptedMetadata: base64.encodeArrayBuffer(encryptedMetadata),
  policyBinding: {
    alg: 'HS256',
    hash: base64.encodeArrayBuffer(policyBinding),
  },
  schemaVersion,
  ephemeralPublicKey: ephemeralPublicKeyPEM,
};
```

### 5. Decrypting Server Responses

When the server responds to the KAS rewrap requests,
the response is decrypted using key agreement and ECDH.
The `unwrapKey` method in `tdf.ts` handles this process.

The server's ephemeral public key is used to derive a shared secret (KEK) with the client's ephemeral private key:

```typescript
const serverEphemeralKey: CryptoKey = await pemPublicToCrypto(sessionPublicKey);
const ekr = ephemeralEncryptionKeysRaw as CryptoKeyPair;
const kek = await keyAgreement(ekr.privateKey, serverEphemeralKey, {
  hkdfSalt: new TextEncoder().encode('salt'),
  hkdfHash: 'SHA-256',
});
```

The encrypted DEK is then decrypted using the derived KEK and the initialization vector (IV) from the response:

```typescript
const wrappedKeyAndNonce = base64.decodeArrayBuffer(entityWrappedKey);
const iv = wrappedKeyAndNonce.slice(0, 12);
const wrappedKey = wrappedKeyAndNonce.slice(12);
const dek = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, kek, wrappedKey);
```

## Conclusion

By using EC encryption and ephemeral key pairs,
we ensure that the DEK is securely transmitted and stored within the ECWrapped KAO.
This approach leverages the strength of ECC and the security of AES-GCM to protect the DEK from unauthorized access.
