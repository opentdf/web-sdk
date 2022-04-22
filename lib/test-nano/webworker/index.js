const logEl = document.getElementById('log');
const worker = new Worker(`worker.js`);

function log(msg, ...data) {
  console.info(msg, data);
  const line = data.reduce((acc, curr) => {
    if (curr) {
      acc += ` [<strong>${JSON.stringify(curr)}</strong>]`;
    }
    return acc;
  }, `${new Date()}\t\t${msg}`);
  logEl.innerHTML = `${logEl.innerHTML}\n${line}`;
}

function handleMessageFromWorker(msg) {
  log('incoming message from worker, msg:', msg.data);

  switch (msg.data.topic) {
    case 'ready':
      sendEncryptPayloadToWorker();
      break;
    case 'do_sendDecrypt':
      log('buff.byteLength post transfer:', msg.data.buff.byteLength);
      handlePlaintextFromWorker(msg.data);
      break;
    default:
      throw 'no topic on incoming message from Worker';
  }
}

function handlePlaintextFromWorker({ buff }) {
  const str = String.fromCharCode.apply(null, new Uint8Array(buff));
  log('plaintext from worker', str);
}

async function sendEncryptPayloadToWorker() {
  const nanotdf = await fetch('../data.txt.tdf');
  const buff = await nanotdf.arrayBuffer();
  log('buff.byteLength pre transfer:', buff.byteLength);
  worker.postMessage(
    {
      topic: 'do_sendDecrypt',
      buff: buff, // The array buffer that we passed to the transferrable section 3 lines below
    },
    [
      buff, // The array buffer we created 9 lines above
    ]
  );
}

worker.addEventListener('message', handleMessageFromWorker);
