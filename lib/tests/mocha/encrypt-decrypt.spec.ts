// import getMocks from '../mocks/index.js';
// import { Client, TDF } from '../../tdf3/src/index.js';
// import * as cryptoService from '../../tdf3/src/crypto/index.js';
// import { createSandbox } from 'sinon';
// import { assert } from 'chai';
// import { Binary } from '../../tdf3/src/binary.js';
// import { HttpRequest } from '../../src/auth/auth.js';
// const Mocks = getMocks();
//
// const authProvider = {
//   // eslint-disable-next-line @typescript-eslint/no-empty-function
//   updateClientPublicKey: async () => {},
//   withCreds: async (httpReq: HttpRequest) => httpReq,
// };
//
// describe('encrypt decrypt test', async function () {
//   const expectedVal = 'hello world';
//   const kasUrl = `http://localhost:4000/`;
//   const kasPublicKey = await TDF.extractPemFromKeyString(Mocks.kasPublicKey);
//
//   it('encrypt-decrypt stream source happy path', async function () {
//     const sandbox = createSandbox();
//     try {
//       const tdf1 = TDF.create({ cryptoService });
//       sandbox.replace(
//         TDF,
//         'create',
//         sandbox.fake(() => tdf1)
//       );
//       sandbox.spy(tdf1, '_generateManifest');
//       sandbox.stub(tdf1, 'unwrapKey').callsFake(async () => {
//         // @ts-ignore
//         const keyInfo = tdf1._generateManifest.lastCall.args[0];
//         return {
//           reconstructedKeyBinary: keyInfo.unwrappedKeyBinary as Binary,
//           metadata: undefined,
//         };
//       });
//       const client = new Client.Client({
//         kasEndpoint: kasUrl,
//         kasPublicKey,
//         keypair: { publicKey: Mocks.entityPublicKey, privateKey: Mocks.entityPrivateKey },
//         clientId: 'id',
//         authProvider,
//       });
//
//       const eo = await Mocks.getEntityObject();
//       const scope = Mocks.getScope();
//
//       const encryptedStream = await client.encrypt({
//         eo,
//         metadata: Mocks.getMetadataObject(),
//         offline: true,
//         scope,
//         source: new ReadableStream({
//           start(controller) {
//             controller.enqueue(new TextEncoder().encode(expectedVal));
//             controller.close();
//           },
//         }),
//       });
//
//       const decryptStream = await client.decrypt({
//         eo,
//         source: {
//           type: 'stream',
//           location: encryptedStream.stream,
//         },
//       });
//
//       const { value: decryptedText } = await decryptStream.stream.getReader().read();
//
//       assert.equal(new TextDecoder().decode(decryptedText), expectedVal);
//     } finally {
//       sandbox.restore();
//     }
//   });
// });
