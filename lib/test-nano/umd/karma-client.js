const expect = chai.expect;
const nano = window.NanoTDF.default;
const getEntityObject = window.NanoTDF.getEntityObject;
const decrypt = window.NanoTDF.decrypt;
const getECKeyPair = window.NanoTDF.getECKeyPair;

window.mocha.setup({ ui: 'tdd' });

let deriveKeyPair;

function benchmark(label) {
  console.time(label);
  const time = new Date().getTime();
  return {
    log: () => console.timeLog(label),
    end: () => {
      console.timeEnd(label);
      return new Date().getTime() - time;
    },
  };
}

async function getFileAB(file) {
  const resp = await fetch(`base/test/${file}`);
  return resp.arrayBuffer();
}

function abToString(data) {
  let view;
  if (data instanceof ArrayBuffer) {
    view = new Uint8Array(data);
  } else if (ArrayBuffer.isView(data)) {
    view = data;
  } else {
    throw new Error('abToString expects ArrayBuffer or TypedArray');
  }

  const encodedString = String.fromCharCode.apply(null, view);
  return decodeURIComponent(escape(encodedString));
}

const EAS_URL = 'https://eas-development.preprod.virtru.com';
const ENTITY_BOB = 'bob_5678';
const ENTITY_CHARLIE = 'Charlie_1234';
const PAGE_FIRST_DECRYPT_TIMEOUT = 1500;
const NEW_EO_DECRYPT_TIMEOUT = 1500;
const REUSE_EO_DECRYPT_TIMEOUT = 800;
const TOTAL_COUNT = 5;

suite('NanoTDF SDK > decrypt', () => {
  let fileAbs = {};

  setup(async () => {
    // load nano file
    fileAbs.basic = await getFileAB('data.txt.tdf');
    fileAbs.attr = await getFileAB('data.attr.tdf');
    fileAbs.json = await getFileAB('data.json.tdf');
    fileAbs.dissem = await getFileAB('data.dissem.tdf');
  });

  test('data.txt.tdf - preprod.virtru.com', async () => {
    const client = new window.NanoTDF.default(EAS_URL, ENTITY_BOB);
    const cleartext = await client.decrypt(fileAbs.basic);
    expect(abToString(cleartext)).eq('hello');
  })
    .slow(PAGE_FIRST_DECRYPT_TIMEOUT)
    .timeout(PAGE_FIRST_DECRYPT_TIMEOUT * 2);

  test('catch error encrypted in different KAS - preprod.virtru.com', async () => {
    const client = new window.NanoTDF.default(EAS_URL, ENTITY_BOB);
    let err;
    try {
      await client.decrypt(fileAbs.json);
    } catch (e) {
      err = e;
    }
    expect(err).to.be.instanceOf(Error);
    expect(err.message).to.contain('Could not rewrap key');
  })
    .slow(PAGE_FIRST_DECRYPT_TIMEOUT)
    .timeout(PAGE_FIRST_DECRYPT_TIMEOUT * 2);

  test('data.attr.tdf - preprod.virtru.com', async () => {
    const client = new window.NanoTDF.default(EAS_URL, ENTITY_BOB);

    const cleartext = await client.decrypt(fileAbs.attr);
    expect(abToString(cleartext)).eq('hello');
  });
  // .slow(NEW_EO_DECRYPT_TIMEOUT)
  // .timeout(NEW_EO_DECRYPT_TIMEOUT * 2);

  test('data.dissem.tdf - preprod.virtru.com', async () => {
    const client = new window.NanoTDF.default(EAS_URL, ENTITY_BOB);

    const cleartext = await client.decrypt(fileAbs.dissem);
    expect(abToString(cleartext)).eq('hello');
  })
    .slow(NEW_EO_DECRYPT_TIMEOUT)
    .timeout(NEW_EO_DECRYPT_TIMEOUT * 2);

  test(`[Performance runs ${TOTAL_COUNT}] with new Entity Object (target ${NEW_EO_DECRYPT_TIMEOUT} ms)`, async () => {
    const client = new window.NanoTDF.default(EAS_URL, ENTITY_CHARLIE);
    const benchmarks = [];

    for (let i = 0; i < TOTAL_COUNT; i++) {
      const { end } = benchmark(`Run performance-decrypt #${i}`);
      // Fetch new entity object
      await client.renewEntityObject();
      await client.decrypt(fileAbs.basic);
      // Mark time
      benchmarks[i] = end();
    }
    const avgTime = benchmarks.reduce((p, c) => p + c, 0) / benchmarks.length;

    console.log(`Benchmarks with new Entity Object ${avgTime}`, benchmarks);
    expect(avgTime).to.be.below(NEW_EO_DECRYPT_TIMEOUT);
  })
    .slow(NEW_EO_DECRYPT_TIMEOUT * TOTAL_COUNT * 2)
    .timeout(1000 + NEW_EO_DECRYPT_TIMEOUT * TOTAL_COUNT * 2);

  test(`[Performance runs ${TOTAL_COUNT}] with existing Entity Object(target ${REUSE_EO_DECRYPT_TIMEOUT} ms)`, async () => {
    const benchmarks = [];
    const client = new window.NanoTDF.default(EAS_URL, ENTITY_CHARLIE);

    // Run first decrypt to fetch EO and Rewrap Key
    await client.decrypt(fileAbs.basic);

    for (let i = 0; i < TOTAL_COUNT; i++) {
      const { end } = benchmark(`Run performance-decrypt #${i}`);
      // Fetch new entity object
      await client.decrypt(fileAbs.basic);
      // Mark time
      benchmarks[i] = end();
    }
    const avgTime = benchmarks.reduce((p, c) => p + c, 0) / benchmarks.length;

    console.log(`Benchmarks existing Entity Object ${avgTime}`, benchmarks);
    expect(avgTime).to.be.below(REUSE_EO_DECRYPT_TIMEOUT);
  })
    .slow(NEW_EO_DECRYPT_TIMEOUT + REUSE_EO_DECRYPT_TIMEOUT * TOTAL_COUNT * 2)
    .timeout(1000 + NEW_EO_DECRYPT_TIMEOUT + REUSE_EO_DECRYPT_TIMEOUT * TOTAL_COUNT * 2);

  test('Test encrypt and decrypt - preprod.virtru.com', async () => {
    const client = new window.NanoTDF.default(EAS_URL, ENTITY_BOB);
    const plainText = 'Virtru!!';
    const cipherText = await client.encrypt(plainText);
    const cleartext = await client.decrypt(cipherText);
    expect(abToString(cleartext)).eq(plainText);
  });

  test('Test encrypt and decrypt - add users and attributes - preprod.virtru.com', async () => {
    const client = new window.NanoTDF.default(EAS_URL, ENTITY_BOB);
    const plainText = 'Virtru!!';
    client.addEntity(ENTITY_CHARLIE);
    client.addAttribute('https://eas.virtru.com/attr/default/value/default');
    const cipherText = await client.encrypt(plainText);

    const differentClient = new window.NanoTDF.default(EAS_URL, ENTITY_CHARLIE);
    const cleartext = await differentClient.decrypt(cipherText);
    expect(abToString(cleartext)).eq(plainText);
  });

  // test("esgaroth.net from nano.tdf", async () => {
  //   const fileResponse = await fetch("../nano.tdf");
  //   const fileAb = await fileResponse.arrayBuffer();
  //   // fetch EntityObject
  //   const entityId = "Alice_1234";
  //   const easEntityObject = "https://eas.eternos.xyz/v1/entity_object";
  //   const entityObject = await getEntityObject(
  //     deriveKeyPair.publicKey,
  //     easEntityObject,
  //     entityId
  //   );
  //   // decrypt nano file
  //   const cleartext = await decrypt(
  //     deriveKeyPair.privateKey,
  //     entityObject,
  //     new Uint8Array(fileAb)
  //   );
  //   expect(abToString(new Uint8Array(cleartext))).eq("hello");
  // });

  // test("from data.json.tdf", async () => {
  //   const fileResponse = await fetch("../data.json.tdf");
  //   const fileAb = await fileResponse.arrayBuffer();
  //   // fetch EntityObject
  //   const entityId = "Alice_1234";
  //   const easEntityObject = "https://eas.eternos.xyz/v1/entity_object";
  //   const entityObject = await getEntityObject(
  //     deriveKeyPair.publicKey,
  //     easEntityObject,
  //     entityId
  //   );
  //   // decrypt nano file
  //   const cleartext = await decrypt(
  //     deriveKeyPair.privateKey,
  //     entityObject,
  //     new Uint8Array(fileAb)
  //   );
  //   expect(abToString(new Uint8Array(cleartext))).eq("hello");
  // });
});
