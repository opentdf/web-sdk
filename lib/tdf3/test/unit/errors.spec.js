import { assert } from 'chai';
import {
  KasDecryptError,
  KasUpsertError,
  KeyAccessError,
  KeySyncError,
  ManifestIntegrityError,
  PolicyIntegrityError,
  TdfDecryptError,
  TdfError,
  TdfPayloadExtractionError,
} from '../../src/errors';

describe('Errors', () => {
  const errorClasses = {
    KasDecryptError,
    KasUpsertError,
    KeyAccessError,
    KeySyncError,
    ManifestIntegrityError,
    PolicyIntegrityError,
    TdfDecryptError,
    TdfError,
    TdfPayloadExtractionError,
  };

  Object.keys(errorClasses).forEach((errorName) => {
    describe(errorName, () => {
      const message = 'test message';
      const err = new errorClasses[errorName](message);

      it('should be instanceof TdfError', () => {
        assert.instanceOf(err, TdfError);
      });

      it('should be instanceof of its own class', () => {
        assert.instanceOf(err, errorClasses[errorName]);
      });

      it('should be instanceof Error', () => {
        assert.instanceOf(err, Error);
      });

      it('should throw correctly', () => {
        assert.throws(() => {
          throw err;
        }, errorClasses[errorName]);
      });

      it('should have the correct name', () => {
        assert.equal(err.name, errorName);
      });

      it('should have the correct message', () => {
        assert.equal(err.message, message);
      });

      it('should have an undefined err', () => {
        assert.equal(err.err, undefined);
      });
    });
  });
});
