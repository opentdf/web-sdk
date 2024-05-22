if (!('document' in globalThis)) {
  // @ts-expect-error // document is either undefined or readonly
  globalThis.document = { documentElement: { style: {} } };
}
