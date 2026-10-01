export type Payload = {
  type: string; // "reference";
  url: string; // "0.payload"
  protocol: string; // "zip"
  isEncrypted: boolean; // true
  mimeType?: string; // e.g. "text/plain"
  // Non-aligned placement of the spec version, declared here in error by some
  // revisions of the JSON schema and known to be written as `null`. Read by
  // resolveSpecVersion; never written.
  tdf_spec_version?: unknown;
};
