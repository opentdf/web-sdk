/* globals hexArrayTag */

const fixtures_basicExample = {
  // 6.1.2 nanotdf Creator's DER encoded Private Key (base64)
  creatorPrivateKey: `
  MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcal1YrV0QohnYoBBlcBLrRETfJlqFOkG
  LSmUOKizW0KhRANCAATVz7l/VSTFkD9ic2IFkzaqcaTC7hbQW3g0A5firgcdLv4sj0OJHZ5zf8U0oUiy
  IrwNU28ahFSfjCTYvzw/bvPg
  `,

  // 6.1.3 Recipient DER encoded Private Key (base64)
  recipientPrivateKey: `
  MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgRywXmrI1J07LZni8xaoKhXj8WbdDHdjd
  N62+tgxjdhihRANCAARon4RjqRNA40eEdBT172emATq3I2siKccLcXl07nTrbAu4enVDo9T4LfQ4eZ0y
  x/KkIX2HylxzkAEoBxzVpBLN
  `,

  // 6.1.4 Recipient Compressed Public Key
  recipientPublicKey: `
  A2ifhGOpE0DjR4R0FPXvZ6YBOrcjayIpxwtxeXTudOts
  `,

  // 6.1.5 nanotdf
  nanotdf: `TDFMAQ5rYXMudmlydHJ1LmNvbYCAAAEVa2FzLnZpcnRydS5jb20vcG9saWN5teQTpgIR5fF7IjSgzT82/3u6bY/o3yP2LJ0JNW+FgvipzxUSbIqdpGxeTgy8yCaXGawFG4BiXMdUAwNv+4KHHwL3f7rlJgnaxejr94bhG3rt1w+JgPlIDH5nHLqrjiRQkgAAEJ69CRdSJo4D+f2AFK98ywYC1c+5f1UkxZA/YnNiBZM2qnGkwu4W0Ft4NAOX4q4HHS6dm4rjMO9wI+pWmbUgS7x9Vo3/+j/6U1fh/NKQ8xrR72LORvDZXfQxa8rzco1Pdc0VlQEL8gQgdKyU3il2ugLz`,

  header: {
    magicNumberVersion: hexArrayTag`4c 31 4c`,
    kas: {
      protocol: 0x01, // Https
      length: 14, // length of "kas.virtru.com"
      body: 'kas.virtru.com',
      hex: hexArrayTag`01 0e 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d`,
    },
    eccBindingMode: {
      useECDSABinding: true,
      ephemeralCurveName: 0x00, // SECP256R1
      hex: hexArrayTag`80`,
    },
    symmetricPayloadConfig: {
      hasSignature: true,
      signatureCurveName: 0x00, // SECP256R1
      symmetricCipher: 0x00, // AES_256_GCM_64
      hex: hexArrayTag`35`,
    },
    remotePolicy: {
      type: 0x00,
      protocol: 0x01,
      urn: 'kas.virtru.com/policy',
      mode: hexArrayTag`00`,
      body: hexArrayTag`01 15 6b 61 73 2e 76 69 72 74 72 75 2e 63 6f 6d 2f 70 6f 6c
      69 63 79`,
      remotePolicy: {
        protocol: 0x01, // Https
        length: 21, // length of "kas.virtru.com"
        body: 'kas.virtru.com/policy',
      },
      binding: hexArrayTag`
        b5 e4 13 a6 02 11 e5 f1 7b 22 34 a0 cd 3f 36 ff 7b ba 6d 8f
        e8 df 23 f6 2c 9d 09 35 6f 85 82 f8 a9 cf 15 12 6c 8a 9d a4
        6c 5e 4e 0c bc c8 26 97 19 ac 05 1b 80 62 5c c7 54 03 03 6f
        fb 82 87 1f
      `,
    },
    ephemeralPublicKey: hexArrayTag`
      02 f7 7f ba e5 26 09 da c5 e8 eb f7 86 e1 1b 7a ed d7 0f 89
      80 f9 48 0c 7e 67 1c ba ab 8e 24 50 92`,
  },

  payload: {
    length: hexArrayTag`00 00 10`,
    iv: hexArrayTag`9e bd 09`,
    ciphertext: hexArrayTag`17 52 26 8e 03`,
    authTag: hexArrayTag`f9 fd 80 14 af 7c cb 06`,
  },

  signature: {
    publicKey: hexArrayTag`
      02 d5 cf b9 7f 55 24 c5 90 3f 62 73 62 05 93 36 aa 71 a4 c2
      ee 16 d0 5b 78 34 03 97 e2 ae 07 1d 2e
    `,
    signature: hexArrayTag`
      9d 9b 8a e3 30 ef 70 23 ea 56 99 b5 20 4b bc 7d 56 8d ff fa
      3f fa 53 57 e1 fc d2 90 f3 1a d1 ef 62 ce 46 f0 d9 5d f4 31
      6b ca f3 72 8d 4f 75 cd 15 95 01 0b f2 04 20 74 ac 94 de 29
      76 ba 02 f3
    `,
  },
};
