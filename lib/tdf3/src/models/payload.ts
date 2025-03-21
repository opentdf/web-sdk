export type Payload = {
  type: string; // "reference";
  url: string; // "0.payload"
  protocol: string; // "zip"
  isEncrypted: boolean; // true
  mimeType?: string; // e.g. "text/plain"
};
