export type ArtifactFinder = {
  upload?: string;
  // Download URL for the payload. This can be a direct link to the file (S3), or a proxy URL.
  download: string;
  key?: string;
  bucket?: string;
};

export type UpsertResponse = {
  uuid: string;
  storageLinks: {
    payload: ArtifactFinder & {
      proxy?: boolean | string;
    };
    metadata?: ArtifactFinder;
  };
}[][];
