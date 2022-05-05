import chai from 'chai';
import { Readable } from 'stream';
import sinon from 'sinon';
import getMocks from '../mocks';

import { Client, TDF } from '../src';

const { assert } = chai;

const Mocks = getMocks();

const kasPublicKey = TDF.extractPemFromKeyString(Mocks.kasPublicKey);

function tdfSandbox() {
  const sandbox = sinon.createSandbox();
  const tdf1 = TDF.create();
  sandbox.replace(
    TDF,
    'create',
    sandbox.fake(() => tdf1)
  );
  sandbox.spy(tdf1, '_generateManifest');
  sandbox.stub(tdf1, 'unwrapKey').callsFake(async (manifest) => {
    assert.nestedProperty(manifest, 'encryptionInformation.keyAccess');
    const keyInfo = tdf1._generateManifest.lastCall.args[0];
    return {
      reconstructedKeyBinary: keyInfo.unwrappedKeyBinary,
      metadata: {},
    };
  });
  return sandbox;
}
