const window = self;

self.importScripts('../../dist/esweb/nanotdf.development.js');

const client = new window.NanoTDF.default('https://eas.eternos.xyz/', 'Alice_1234');

self.postMessage({ topic: 'ready' });

self.onmessage = (msg) => {
  switch (msg.data.topic) {
    case 'do_sendDecrypt':
      handleDecrypt(msg.data);
      break;
    default:
      throw 'no topic on incoming message to WebWorker';
  }
};

async function handleDecrypt({ buff: ct }) {
  console.info('from worker, PRE send decrypt back ct.byteLength', ct.byteLength);

  const pt = await client.decrypt(ct);

  self.postMessage({ topic: 'do_sendDecrypt', buff: pt });

  console.info('from worker, POST send decrypt back pt.byteLength', pt.byteLength);
}
