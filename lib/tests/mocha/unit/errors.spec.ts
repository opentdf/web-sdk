import { assert } from 'chai';
import {
  AssertionVerificationError,
  DecryptError,
  IntegrityError,
  InvalidFileError,
  IvExhaustionError,
  TdfError,
} from '../../../src/errors.js';

function causeOf(error: unknown): unknown {
  return error instanceof Error ? (error as Error & { cause?: unknown }).cause : undefined;
}

describe('Errors', () => {
  const errorClasses: Record<string, typeof TdfError> = {
    DecryptError,
    IntegrityError,
    IvExhaustionError,
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

  describe('AssertionVerificationError', () => {
    it('is an IntegrityError with a reason, the exact id, and both in its message', () => {
      const e = new AssertionVerificationError('binding-mismatch', 'detail', 'a1');
      assert.instanceOf(e, IntegrityError);
      assert.instanceOf(e, InvalidFileError);
      assert.equal(e.name, 'AssertionVerificationError');
      assert.equal(e.reason, 'binding-mismatch');
      assert.equal(e.assertionId, 'a1');
      assert.equal(
        e.message,
        'assertion integrity check failed, id: a1, reason=binding-mismatch: detail'
      );
    });

    it('omits the id when there is none', () => {
      const e = new AssertionVerificationError('duplicate-member');
      assert.equal(e.assertionId, undefined);
      assert.equal(e.message, 'assertion integrity check failed, reason=duplicate-member');
    });

    it('escapes backslashes and control characters in the rendered id', () => {
      const id = 'a1\nreason=signature-invalid\t\\\u0000\u001b\u007f\u009f é';
      const e = new AssertionVerificationError('binding-mismatch', undefined, id);
      assert.equal(e.assertionId, id);
      assert.notInclude(e.message, '\n');
      assert.equal(
        e.message,
        'assertion integrity check failed, id: a1\\nreason=signature-invalid\\t\\\\\\u0000\\u001b\\u007f\\u009f é, reason=binding-mismatch'
      );
    });

    it('shortens a long rendered id to 256 code points', () => {
      const id = '😀'.repeat(300);
      const e = new AssertionVerificationError('invalid-binding', undefined, id);
      assert.equal(e.assertionId, id);
      assert.include(e.message, `id: ${'😀'.repeat(256)}…, reason=invalid-binding`);
      const exact = 'x'.repeat(256);
      assert.include(
        new AssertionVerificationError('invalid-binding', undefined, exact).message,
        `id: ${exact}, reason=`
      );
    });
  });
});
