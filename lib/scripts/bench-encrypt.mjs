#!/usr/bin/env node
// Encrypt throughput and peak memory of the SDK's own `writeStream`, swept
// over segment sizes.
//
//   npm run build              # needs dist/web
//   npm run bench:encrypt
//   npm run bench:encrypt -- --total 4GiB --chunk 64KiB --segments 2MiB,256MiB
//   npm run bench:encrypt -- --lib . --lib /path/to/other/lib   # compare two builds
//
// Each segment size runs in its own child process, so the reported peak RSS
// belongs to that cell alone. The key access objects are stubbed out, so no
// KAS or network is involved: what is measured is chunking, AES-GCM, segment
// integrity, CRC-32 and ZIP framing. The output is counted and discarded as
// it is read; a cell fails if the output is too short to hold the input.
//
// The CRC-32 column is measured separately, once per build, in this parent
// process over a 256 MiB buffer.
//
// The input arrives in `--chunk`-sized pieces, each a fresh buffer. The
// default of 64 KiB is typical of browser `File.stream()` and is the Node file
// stream default; a large chunk size hides per-chunk costs.
//
// Numbers are only comparable between runs on the same machine. To compare
// two builds, run this script once per build, or pass `--lib` twice.

import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import path from 'node:path';

const UNITS = { b: 1, kib: 2 ** 10, mib: 2 ** 20, gib: 2 ** 30 };
const MiB = 2 ** 20;
// AES-GCM adds a 12-byte IV and a 16-byte tag to every segment.
const SEGMENT_OVERHEAD = 12 + 16;

function parseSize(text) {
  const m = /^(\d+)\s*([a-z]*)$/i.exec(String(text).trim());
  const unit = m && (m[2].toLowerCase() || 'b');
  if (!m || !(unit in UNITS) || Number(m[1]) === 0) {
    throw new Error(`invalid size [${text}]; use a positive byte count or KiB/MiB/GiB`);
  }
  return Number(m[1]) * UNITS[unit];
}

function label(n) {
  for (const [u, s] of [
    ['GiB', 2 ** 30],
    ['MiB', 2 ** 20],
    ['KiB', 2 ** 10],
  ]) {
    if (n % s === 0) return `${n / s}${u}`;
  }
  return `${n}B`;
}

async function importLib(lib) {
  const dist = path.join(lib, 'dist', 'web');
  const load = (p) => import(pathToFileURL(path.join(dist, p)).href);
  const [{ writeStream }, { SplitKey }, { AesGcmCipher }, { DefaultCryptoService }, crc] =
    await Promise.all([
      load('tdf3/src/tdf.js'),
      load('tdf3/src/models/encryption-information.js'),
      load('tdf3/src/ciphers/aes-gcm-cipher.js'),
      load('tdf3/src/crypto/index.js'),
      load('tdf3/src/utils/buffer-crc32.js'),
    ]);
  return {
    writeStream,
    SplitKey,
    AesGcmCipher,
    DefaultCryptoService,
    crc32: crc.unsigned,
    crc32Backend: crc.crc32Backend ?? 'portable',
  };
}

// Child: one measurement, one JSON line on stdout.
async function cell({ lib, segment, chunk, total }) {
  const { writeStream, SplitKey, AesGcmCipher, DefaultCryptoService } = await importLib(lib);
  const ei = new SplitKey(new AesGcmCipher(DefaultCryptoService));
  ei.getKeyAccessObjects = async () => [];
  const key = await ei.generateKey();

  let sent = 0;
  const contentStream = new ReadableStream({
    pull(c) {
      if (sent >= total) return c.close();
      const n = Math.min(chunk, total - sent);
      c.enqueue(new Uint8Array(n));
      sent += n;
    },
  });

  const t0 = performance.now();
  const s = await writeStream({
    auth: {},
    cryptoService: DefaultCryptoService,
    encryptionInformation: ei,
    segmentSizeDefault: segment,
    rootIntegrityAlgorithm: 'HS256',
    segmentIntegrityAlgorithm: 'GMAC',
    contentStream,
    policy: {
      uuid: '00000000-0000-0000-0000-000000000000',
      body: { dataAttributes: [], dissem: [] },
    },
    byteLimit: Number.MAX_SAFE_INTEGER,
    keyForEncryption: key,
    keyForManifest: key,
  });
  const r = s.stream.getReader();
  let out = 0;
  for (;;) {
    const { done, value } = await r.read();
    if (done) break;
    out += value.length;
  }
  const seconds = (performance.now() - t0) / 1000;
  // A build that drops plaintext would otherwise just look faster.
  const minOut = total + Math.ceil(total / segment) * SEGMENT_OVERHEAD;
  if (out < minOut) {
    throw new Error(
      `wrote ${out} bytes for ${total} bytes of plaintext; expected at least ${minOut}`
    );
  }
  return {
    segment,
    chunk,
    total,
    out,
    seconds,
    mibPerSec: total / MiB / seconds,
    maxRssMiB: process.resourceUsage().maxRSS / 1024,
  };
}

async function crcThroughput(lib) {
  const { crc32, crc32Backend } = await importLib(lib);
  const buf = new Uint8Array(256 * MiB);
  crc32(buf.subarray(0, MiB), 0);
  const t0 = performance.now();
  crc32(buf, 0);
  return `${(256 / ((performance.now() - t0) / 1000)).toFixed(0)} (${crc32Backend})`;
}

function parseArgs(argv) {
  const opts = { libs: [], total: 2 ** 30, chunk: 64 * 2 ** 10, segments: null, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) throw new Error(`${a} needs a value`);
      return argv[++i];
    };
    if (a === '--lib') opts.libs.push(path.resolve(next()));
    else if (a === '--total') opts.total = parseSize(next());
    else if (a === '--chunk') opts.chunk = parseSize(next());
    else if (a === '--segments') opts.segments = next().split(',').map(parseSize);
    else if (a === '--json') opts.json = true;
    else if (a === '--cell') opts.cell = JSON.parse(next());
    else if (a === '-h' || a === '--help') opts.help = true;
    else throw new Error(`unknown argument [${a}]`);
  }
  if (!opts.libs.length) {
    opts.libs.push(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'));
  }
  opts.segments ??= [2, 16, 64, 256].map((n) => n * MiB);
  return opts;
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    console.log(
      'usage: bench-encrypt.mjs [--lib DIR]... [--total 1GiB] [--chunk 64KiB] ' +
        '[--segments 2MiB,16MiB,64MiB,256MiB] [--json]'
    );
    return;
  }
  if (opts.cell) {
    process.stdout.write(JSON.stringify(await cell(opts.cell)) + '\n');
    return;
  }

  const rows = [];
  for (const lib of opts.libs) {
    const crc = await crcThroughput(lib);
    for (const segment of opts.segments) {
      const args = { lib, segment, chunk: opts.chunk, total: opts.total };
      const child = spawnSync(
        process.execPath,
        [fileURLToPath(import.meta.url), '--cell', JSON.stringify(args)],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] }
      );
      if (child.status !== 0) {
        rows.push({
          lib,
          segment,
          error: child.error?.message ?? `exit ${child.status ?? child.signal}`,
        });
        continue;
      }
      rows.push({ lib, crc32: crc, ...JSON.parse(child.stdout) });
    }
  }

  if (rows.some((r) => r.error)) process.exitCode = 1;
  if (opts.json) {
    for (const row of rows) console.log(JSON.stringify(row));
    return;
  }
  console.log(
    `node ${process.version}, ${label(opts.total)} plaintext in ${label(opts.chunk)} chunks\n`
  );
  console.log('| lib | CRC-32 MiB/s | segment | encrypt MiB/s | peak RSS MiB |');
  console.log('| --- | ---: | ---: | ---: | ---: |');
  for (const r of rows) {
    const cols = r.error
      ? ['', label(r.segment), r.error, '']
      : [r.crc32, label(r.segment), r.mibPerSec.toFixed(0), r.maxRssMiB.toFixed(0)];
    console.log(`| ${r.lib} | ${cols.join(' | ')} |`);
  }
}

await main();
