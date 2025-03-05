const generateSalt = async () => {
  const encoder = new TextEncoder();
  const data = encoder.encode('TDF');

  // Generate hash
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);

  return new Uint8Array(hashBuffer);
};

export const ztdfSalt = generateSalt();
