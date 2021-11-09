/* globals window describe it chai bufferToHex fixtures_basicExample */
const expect = chai.expect;
const { nanotdf, easUrl } = fixtures_client;

describe('NanoTDF Client', () => {
  it('should initalize client', () => {
    const client = new NanoTDFClient.Client(easUrl, entityId);
    client.fetch;
  });
});
