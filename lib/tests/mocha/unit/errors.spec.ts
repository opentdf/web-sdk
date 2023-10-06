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
} from '../../../src/errors.js';

describe('Errors', () => {
  const errorClasses: Record<string, typeof TdfError> = {
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
        assert.equal(err.cause, undefined);
      });
    });
  });
});

describe('scrubbing causes', () => {
  it('Removes unsupported fields', () => {
    const cause = new Error();
    cause.message = 'my message';
    (cause as unknown as Record<string, string>).extra = 'some_stuff';
    try {
      throw new TdfError('message', cause);
    } catch (e) {
      assert.equal(e.message, 'message');
      assert.equal(e.cause.extra, undefined);
      assert.equal(e.cause.message, 'my message');
      assert.equal(e.cause.cause, undefined);
      assert.equal(e.cause.stack, cause.stack);
    }
  });

  it('Avoids errors due to loops', () => {
    const cause = new Error();
    cause.message = 'my message';
    (cause as unknown as Record<string, string>).extra = 'some_stuff';
    cause.cause = cause;
    try {
      throw new TdfError('message', cause);
    } catch (e) {
      assert.equal(e.message, 'message');
      assert.equal(e.cause.extra, undefined);
      assert.equal(e.cause.message, 'my message');
      assert.equal(e.cause.stack, cause.stack);
      assert.equal(e.cause.cause.stack, cause.stack);
      assert.equal(e.cause.cause.cause.stack, cause.stack);
      assert.equal(e.cause.cause.cause.cause.stack, cause.stack);
      assert.equal(e.cause.cause.cause.cause.cause.stack, cause.stack);
      assert.equal(e.cause.cause.cause.cause.cause.cause, undefined);
    }
  });
});
