import { expect } from 'chai';
import sinon from 'sinon';
import * as TDF from '../../tdf3/src/tdf.js';
import { ConfigurationError, InvalidFileError, NetworkError, PermissionDeniedError, ServiceError, UnauthenticatedError, UnsafeUrlError, DecryptError } from '../../src/errors.js';
import { OriginAllowList } from '../../src/access.js';
import type { AuthProvider, AppIdAuthProvider } from '../../src/auth/auth.js';
import { CryptoService, CryptoKeyPair, EntityObject } from '../../tdf3/index.js';

describe('unwrapKey', () => {
  let manifest, allowedKases, authProvider, dpopKeys, entity, cryptoService;

  beforeEach(() => {
    manifest = { encryptionInformation: { keyAccess: [], policy: {}, integrityInformation: {} } };
    allowedKases = new OriginAllowList(['https://kas1']);
    authProvider = sinon.createStubInstance(AuthProvider);
    dpopKeys = { privateKey: 'privateKey' } as CryptoKeyPair;
    entity = {} as EntityObject;
    cryptoService = sinon.createStubInstance(CryptoService);
  });

  it('throws ConfigurationError if authProvider is undefined', async () => {
    authProvider = undefined;
    await expect(TDF.unwrapKey({ manifest, allowedKases, authProvider, dpopKeys, entity, cryptoService }))
      .to.be.rejectedWith(ConfigurationError, 'upsert requires auth provider; must be configured in client constructor');
  });

  it('throws UnsafeUrlError if no valid KAS found for split', async () => {
    manifest.encryptionInformation.keyAccess = [{ sid: 'split1', url: 'https://kas2' }];
    await expect(TDF.unwrapKey({ manifest, allowedKases, authProvider, dpopKeys, entity, cryptoService }))
      .to.be.rejectedWith(UnsafeUrlError, 'Unreconstructable key - no valid KAS found for split "split1"');
  });

  it('throws ServiceError on rewrap failure with status >= 500', async () => {
    manifest.encryptionInformation.keyAccess = [{ sid: 'split1', url: 'https://kas1' }];
    authProvider.withCreds.resolves({ url: 'https://kas1/rewrap', body: {}, headers: {} });
    axios.post.rejects({ response: { status: 500 } });
    await expect(TDF.unwrapKey({ manifest, allowedKases, authProvider, dpopKeys, entity, cryptoService }))
      .to.be.rejectedWith(ServiceError, 'rewrap failure');
  });

  it('throws PermissionDeniedError on rewrap failure with status 403', async () => {
    manifest.encryptionInformation.keyAccess = [{ sid: 'split1', url: 'https://kas1' }];
    authProvider.withCreds.resolves({ url: 'https://kas1/rewrap', body: {}, headers: {} });
    axios.post.rejects({ response: { status: 403 } });
    await expect(TDF.unwrapKey({ manifest, allowedKases, authProvider, dpopKeys, entity, cryptoService }))
      .to.be.rejectedWith(PermissionDeniedError, 'rewrap failure');
  });

  it('throws UnauthenticatedError on rewrap failure with status 401', async () => {
    manifest.encryptionInformation.keyAccess = [{ sid: 'split1', url: 'https://kas1' }];
    authProvider.withCreds.resolves({ url: 'https://kas1/rewrap', body: {}, headers: {} });
    axios.post.rejects({ response: { status: 401 } });
    await expect(TDF.unwrapKey({ manifest, allowedKases, authProvider, dpopKeys, entity, cryptoService }))
      .to.be.rejectedWith(UnauthenticatedError, 'rewrap auth failure');
  });

  it('throws InvalidFileError on rewrap failure with status 400', async () => {
    manifest.encryptionInformation.keyAccess = [{ sid: 'split1', url: 'https://kas1' }];
    authProvider.withCreds.resolves({ url: 'https://kas1/rewrap', body: {}, headers: {} });
    axios.post.rejects({ response: { status: 400 } });
    await expect(TDF.unwrapKey({ manifest, allowedKases, authProvider, dpopKeys, entity, cryptoService }))
      .to.be.rejectedWith(InvalidFileError, 'rewrap bad request; could indicate an invalid policy binding or a configuration error');
  });

  it('throws NetworkError on rewrap request failure', async () => {
    manifest.encryptionInformation.keyAccess = [{ sid: 'split1', url: 'https://kas1' }];
    authProvider.withCreds.resolves({ url: 'https://kas1/rewrap', body: {}, headers: {} });
    axios.post.rejects({ request: {} });
    await expect(TDF.unwrapKey({ manifest, allowedKases, authProvider, dpopKeys, entity, cryptoService }))
      .to.be.rejectedWith(NetworkError, 'rewrap request failure');
  });

  it('throws DecryptError on rewrap failure with InvalidAccessError or OperationError', async () => {
    manifest.encryptionInformation.keyAccess = [{ sid: 'split1', url: 'https://kas1' }];
    authProvider.withCreds.resolves({ url: 'https://kas1/rewrap', body: {}, headers: {} });
    axios.post.rejects({ name: 'InvalidAccessError' });
    await expect(TDF.unwrapKey({ manifest, allowedKases, authProvider, dpopKeys, entity, cryptoService }))
      .to.be.rejectedWith(DecryptError, 'unable to unwrap key from kas');
  });

  it('returns reconstructedKeyBinary and metadata on successful unwrap', async () => {
    manifest.encryptionInformation.keyAccess = [{ sid: 'split1', url: 'https://kas1' }];
    authProvider.withCreds.resolves({ url: 'https://kas1/rewrap', body: {}, headers: {} });
    axios.post.resolves({ data: { entityWrappedKey: 'wrappedKey', metadata: 'metadata' } });
    cryptoService.decryptWithPrivateKey.resolves(new Uint8Array([1, 2, 3]));
    const result = await TDF.unwrapKey({ manifest, allowedKases, authProvider, dpopKeys, entity, cryptoService });
    expect(result.reconstructedKeyBinary).to.deep.equal(new Uint8Array([1, 2, 3]));
    expect(result.metadata).to.equal('metadata');
  });
});
