import { expect } from 'chai';
import { Code, ConnectError } from '@connectrpc/connect';
import {
  handleRpcRewrapError,
  handleRpcRewrapErrorString,
} from '../../../src/access/access-rpc.js';
import { PermissionDeniedError } from '../../../src/errors.js';

const platformUrl = 'https://platform.example';
const deniedMessage = `403 for [${platformUrl}]; rewrap permission denied: forbidden`;

function errorThrownBy(handle: () => never): unknown {
  try {
    handle();
  } catch (e) {
    return e;
  }
  return expect.fail('should have thrown');
}

describe('rewrap errors', () => {
  it('keeps the reason of a denied key access object result', () => {
    const result = 'rpc error: code = PermissionDenied desc = forbidden: pdp-denied';
    const error = errorThrownBy(() => handleRpcRewrapErrorString(result, platformUrl));
    expect(error).to.be.instanceOf(PermissionDeniedError);
    const denied = error as PermissionDeniedError;
    expect(denied.message).to.equal(deniedMessage);
    expect(denied.reason).to.equal(result);
    expect(denied.requiredObligations).to.equal(undefined);
  });

  it('keeps the reason along with the required obligations', () => {
    const result = 'rpc error: code = PermissionDenied desc = forbidden';
    const obligations = ['https://example.com/obl/obligation1'];
    const error = errorThrownBy(() => handleRpcRewrapErrorString(result, platformUrl, obligations));
    expect(error).to.be.instanceOf(PermissionDeniedError);
    const denied = error as PermissionDeniedError;
    expect(denied.message).to.equal(deniedMessage);
    expect(denied.reason).to.equal(result);
    expect(denied.requiredObligations).to.deep.equal(obligations);
  });

  it('keeps the reason of a denied rewrap call', () => {
    const error = errorThrownBy(() =>
      handleRpcRewrapError(
        new ConnectError('forbidden: pdp-denied', Code.PermissionDenied),
        platformUrl
      )
    );
    expect(error).to.be.instanceOf(PermissionDeniedError);
    const denied = error as PermissionDeniedError;
    expect(denied.message).to.equal(deniedMessage);
    expect(denied.reason).to.equal('forbidden: pdp-denied');
  });
});

describe('PermissionDeniedError', () => {
  it('has no reason unless one is given', () => {
    expect(new PermissionDeniedError('denied').reason).to.equal(undefined);
    expect(new PermissionDeniedError('denied', undefined, undefined, '').reason).to.equal(
      undefined
    );
  });
});
