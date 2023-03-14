
self.onmessage = ({ data: { chunk } }) => {
  const workerResult = `Result: ${chunk}`;
  console.log('Message received from main script: ', workerResult);
  console.log('Posting message back to main script');
  postMessage('Hi this is worker, thanks for the message');
}

addEventListener("message", (message) => {
  console.log("Worker recieved: ", message.data.chunk);
  postMessage('Hi this is worker, thanks for the message');
});
