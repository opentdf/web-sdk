import { assert } from 'chai';
import { DecryptError, IntegrityError, TdfError } from '../../../src/errors.js';

function causeOf(error: unknown): unknown {
  return error instanceof Error ? (error as Error & { cause?: unknown }).cause : undefined;
}

describe('Errors', () => {
  const errorClasses: Record<string, typeof TdfError> = {
    DecryptError,
    IntegrityError,
    TdfError,
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

      it('should be instanceof TdfError', () => {
        assert.instanceOf(err, TdfError);
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
      assert.instanceOf(e, TdfError);
      if (!(e instanceof TdfError)) return;
      assert.equal(e.message, 'message');
      const scrubbedCause = causeOf(e);
      assert.instanceOf(scrubbedCause, Error);
      if (!(scrubbedCause instanceof Error)) return;
      assert.equal((scrubbedCause as Error & { extra?: unknown }).extra, undefined);
      assert.equal(scrubbedCause.message, 'my message');
      assert.equal(causeOf(scrubbedCause), undefined);
      assert.equal(scrubbedCause.stack, cause.stack);
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
      assert.instanceOf(e, TdfError);
      if (!(e instanceof TdfError)) return;
      assert.equal(e.message, 'message');
      let scrubbedCause: unknown = causeOf(e);
      assert.instanceOf(scrubbedCause, Error);
      if (!(scrubbedCause instanceof Error)) return;
      assert.equal((scrubbedCause as Error & { extra?: unknown }).extra, undefined);
      assert.equal(scrubbedCause.message, 'my message');
      for (let depth = 0; depth < 5; depth += 1) {
        assert.instanceOf(scrubbedCause, Error);
        if (!(scrubbedCause instanceof Error)) return;
        assert.equal(scrubbedCause.stack, cause.stack);
        scrubbedCause = causeOf(scrubbedCause);
      }
      assert.equal(scrubbedCause, undefined);
    }
  });
});
