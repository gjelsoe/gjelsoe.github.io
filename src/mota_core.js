/* mota_core.js — browser/Node core for the MeshCore "push an update to one node" page.
 *
 * Builds format-v3 `.mota` containers byte-identical to tools/mota/motalib.py and motatool, serves them to a
 * node over the `mota-seeder` link (src/helpers/ota/MotaSeederProto.h), and schedules `ota nudge` console
 * lines (method A, docs/ota_protocol.md §8.7). No network access, no credentials: the signing key never
 * leaves the page.
 *
 * Dependencies are injected (see MotaCore.init) so the same file runs in the page, a Web Worker and Node:
 *   bsdiff/pack/crle : vendor/detools-js (MIT)          — delta encoding
 *   ed               : vendor/noble-ed25519 2.3.0 (MIT)  — Ed25519 signing
 *   subtle           : WebCrypto SubtleCrypto            — SHA-256
 *   lzma             : vendor/lzma-js (MIT, LZMA-JS 2.3.2) — LZMA wrapper for codec 3
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api; else root.MotaCore = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // ---- constants (docs/ota_protocol.md, OtaFormat.h, motalib.py) ----------------------------------------
  const MAGIC = Uint8Array.of(0x6d, 0x4f, 0x54, 0x41);            // "mOTA"
  const TRAILER = Uint8Array.of(0x76, 0x6b, 0x34, 0x39, 0x36);    // "vk496"
  const ENDF_MAGIC = Uint8Array.of(0x45, 0x6e, 0x64, 0x46);       // "EndF"
  const ENDF_LEN = 56;
  const FORMAT_VER = 3, HASH_LEN = 8, MFL = 233, SIGNED_LEN = 165, HEADER_LEN = 8;
  const HASH_ALGO_SHA256 = 0x12, FLAG_FULL = 0x01, FLAG_SIGNED = 0x02;
  const CODEC = { FULL: 0, SEQUENTIAL: 1, INPLACE: 2, SEQUENTIAL_LZMA: 3 };
  const OFF = { FORMAT_VER: 0, FLAGS: 1, HASH_ALGO: 2, TARGET_ID: 3, FW_VERSION: 7, IMAGE_SIZE: 11,
    PAYLOAD_SIZE: 15, BLOCK_SIZE_LOG2: 19, MERKLE_ROOT: 20, IMAGE_HASH: 28, PAYLOAD_HASH: 60, CODEC_ID: 92,
    HW_ID: 93, BASE_HASH: 125, SIGNER: 133, SIGNATURE: 165, APPROVAL: 229 };
  const BLOCK_SIZE = 1024;
  const NRF52_INPLACE_MEMORY = 0x98000, NRF52_SEGMENT = 4096;
  // Bootloader STAGE_TOP (0xD3000) - APP_BASE (0x26000) - in-place window: the largest in-place .mota that
  // still stages below the apply journal (motatool format.rs NRF52_MAX_INPLACE_MOTA).
  const NRF52_MAX_INPLACE_MOTA = (0xD3000 - 0x26000) - NRF52_INPLACE_MEMORY;

  const SEEDER = { REQ0: 0x4d, REQ1: 0x53, RSP0: 0x6d, RSP1: 0x73, OP_COUNT: 1, OP_DESCRIBE: 2, OP_READ: 3,
    OP_STAT: 4, OP_BEGIN: 5, OP_WRITE: 6, OP_SREAD: 7, OP_FIN: 8, OK: 0, ERR: 1, DESC_WIRE: 38, WRITE_MAX: 512 };
  const NUDGE_PREFIX = 6;

  let dep = { bsdiff: null, pack: null, crle: null, ed: null, subtle: null, lzma: null };
  function init(d) { dep = Object.assign({}, dep, d); return api; }

  // ---- bytes ---------------------------------------------------------------------------------------------
  const concat = (parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  };
  const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
  const toHex = (b) => Array.from(b, (v) => v.toString(16).padStart(2, '0')).join('').toUpperCase();
  function fromHex(s) {
    s = String(s).trim().replace(/^0x/i, '');
    if (s.length % 2 || /[^0-9a-f]/i.test(s)) throw new Error('not a hex string');
    return Uint8Array.from(s.match(/../g) || [], (h) => parseInt(h, 16));
  }
  const rdU32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
  const wrU32 = (b, o, v) => { b[o] = v & 255; b[o + 1] = (v >>> 8) & 255; b[o + 2] = (v >>> 16) & 255; b[o + 3] = (v >>> 24) & 255; };
  const u32le = (v) => { const b = new Uint8Array(4); wrU32(b, 0, v >>> 0); return b; };
  async function sha256(data) { return new Uint8Array(await dep.subtle.digest('SHA-256', data)); }
  const mh = async (data, n) => (await sha256(data)).slice(0, n);

  // ---- firmware input -------------------------------------------------------------------------------------
  /** Intel HEX -> flat image over [min, max) with gaps 0xFF (motatool input.rs). */
  function parseIntelHex(text) {
    let base = 0, lo = Infinity, hi = 0, eof = false; const segs = [];
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line) continue;
      if (line[0] !== ':') throw new Error('malformed Intel HEX line');
      const rec = fromHex(line.slice(1));
      const n = rec[0], addr = (rec[1] << 8) | rec[2], type = rec[3];
      if (rec.length !== n + 5) throw new Error('Intel HEX record length mismatch');
      let sum = 0; for (const v of rec) sum = (sum + v) & 255;
      if (sum !== 0) throw new Error('Intel HEX checksum error');
      const data = rec.subarray(4, 4 + n);
      if (type === 0) { const a = base + addr; lo = Math.min(lo, a); hi = Math.max(hi, a + n); segs.push([a, data]); }
      else if (type === 1) { eof = true; break; }
      else if (type === 2) base = ((data[0] << 8) | data[1]) << 4;
      else if (type === 4) base = (((data[0] << 8) | data[1]) << 16) >>> 0;
    }
    if (!segs.length) throw new Error('no data records in Intel HEX');
    if (!eof) throw new Error('Intel HEX missing EOF record');
    const out = new Uint8Array(hi - lo).fill(0xff);
    for (const [a, d] of segs) out.set(d, a - lo);
    return out;
  }

  /** Cut a flat image right after its EndF trailer (UF2 pads the last block with 0xFF); unchanged if none. */
  function cutAtEndF(img) {
    for (let k = img.length - ENDF_LEN; k >= 0; k--) {
      if (img[k] !== ENDF_MAGIC[0] || !equal(img.subarray(k, k + 4), ENDF_MAGIC)) continue;
      if (rdU32(img, k + 4) === k) return img.subarray(0, k + ENDF_LEN);   // body_len == offset: the app's own
    }
    return img;
  }
  /** UF2 (what the nRF52 build drags onto the bootloader drive) -> flat app image from its lowest address. */
  function parseUf2(buf) {
    const MAG0 = 0x0A324655, MAG1 = 0x9E5D5157, MAGE = 0x0AB16F30, FLAG_NOFLASH = 0x1;
    if (buf.length < 512 || buf.length % 512) throw new Error('not a UF2 file (size is not a multiple of 512)');
    const parts = []; let lo = Infinity, hi = 0;
    for (let o = 0; o < buf.length; o += 512) {
      const b = buf.subarray(o, o + 512);
      if (rdU32(b, 0) !== MAG0 || rdU32(b, 4) !== MAG1 || rdU32(b, 508) !== MAGE) throw new Error('not a UF2 file (bad block magic)');
      if (rdU32(b, 8) & FLAG_NOFLASH) continue;
      const addr = rdU32(b, 12), n = rdU32(b, 16);
      if (n > 476) throw new Error('UF2 block payload too large');
      parts.push([addr, b.subarray(32, 32 + n)]); lo = Math.min(lo, addr); hi = Math.max(hi, addr + n);
    }
    if (!parts.length) throw new Error('UF2 has no flash data');
    const out = new Uint8Array(hi - lo).fill(0xff);
    for (const [a, d] of parts) out.set(d, a - lo);
    return cutAtEndF(out);
  }
  /** One entry of a ZIP file by name (stored or deflate; DecompressionStream('deflate-raw')). */
  async function unzipEntry(buf, name) {
    let e = -1;
    for (let k = buf.length - 22; k >= Math.max(0, buf.length - 22 - 65535); k--) if (rdU32(buf, k) === 0x06054b50) { e = k; break; }
    if (e < 0) throw new Error('not a ZIP file');
    const n = buf[e + 10] | (buf[e + 11] << 8);
    let c = rdU32(buf, e + 16);
    for (let i = 0; i < n; i++) {
      if (rdU32(buf, c) !== 0x02014b50) throw new Error('bad ZIP central directory');
      const method = buf[c + 10] | (buf[c + 11] << 8), csize = rdU32(buf, c + 20), usize = rdU32(buf, c + 24);
      const nl = buf[c + 28] | (buf[c + 29] << 8), xl = buf[c + 30] | (buf[c + 31] << 8), cl = buf[c + 32] | (buf[c + 33] << 8);
      const lho = rdU32(buf, c + 42), fname = new TextDecoder().decode(buf.subarray(c + 46, c + 46 + nl));
      c += 46 + nl + xl + cl;
      if (fname !== name && !fname.endsWith('/' + name)) continue;
      if (rdU32(buf, lho) !== 0x04034b50) throw new Error('bad ZIP local header');
      const d0 = lho + 30 + (buf[lho + 26] | (buf[lho + 27] << 8)) + (buf[lho + 28] | (buf[lho + 29] << 8));
      const raw = buf.subarray(d0, d0 + csize);
      let out;
      if (method === 0) out = raw.slice();
      else if (method === 8) {
        const ds = new DecompressionStream('deflate-raw');
        out = new Uint8Array(await new Response(new Blob([raw]).stream().pipeThrough(ds)).arrayBuffer());
      } else throw new Error(`ZIP compression method ${method} not supported`);
      if (out.length !== usize) throw new Error('ZIP entry size mismatch');
      return out;
    }
    return null;
  }
  /** nRF52 DFU package (.zip from the build: manifest.json + firmware.bin + .dat) -> its application image. */
  async function parseDfuZip(buf) {
    let binName = 'firmware.bin';
    const mf = await unzipEntry(buf, 'manifest.json');
    if (mf) {
      try { binName = JSON.parse(new TextDecoder().decode(mf)).manifest.application.bin_file || binName; } catch (e) {}
    }
    const bin = await unzipEntry(buf, binName);
    if (!bin) throw new Error(`DFU zip has no ${binName}`);
    return cutAtEndF(bin);
  }

  /** The firmware's self-describing EndF trailer, or null when absent/inconsistent. */
  async function parseEndF(image) {
    if (image.length < ENDF_LEN) return null;
    const t = image.subarray(image.length - ENDF_LEN);
    if (!equal(t.subarray(0, 4), ENDF_MAGIC) || rdU32(t, 4) !== image.length - ENDF_LEN) return null;
    const bodyHash = t.slice(8, 16);
    if (!equal(await mh(image.subarray(0, image.length - ENDF_LEN), 8), bodyHash)) return null;
    let hw = t.subarray(24, 56); const z = hw.indexOf(0); if (z >= 0) hw = hw.subarray(0, z);
    return { bodyHash, fwVersion: rdU32(t, 16), targetId: rdU32(t, 20), hwId: String.fromCharCode(...hw) };
  }
  const versionStr = (v) => `${v >>> 24}.${(v >>> 16) & 255}.${(v >>> 8) & 255}` + ((v & 255) ? `-${v & 255}` : '');

  // ---- delta encoders (detools sequential / in-place, CRLE) ------------------------------------------------
  // Same stream layout as motatool encode.rs; output decodes with detools.apply_patch[_in_place].
  function controlData(from, to) {
    const parts = [dep.pack.packSize(0)];                          // data-format = none
    for (const c of dep.bsdiff.createControl(from, to))
      parts.push(dep.pack.packSize(c.diff.length), c.diff, dep.pack.packSize(c.extra.length), c.extra,
        dep.pack.packSize(c.adjustment));
    return concat(parts);
  }
  function encodeSequential(from, to) {
    return concat([Uint8Array.of(0x02), dep.pack.packSize(to.length), dep.crle.compress(controlData(from, to))]);
  }
  function encodeInPlace(from, to, memory = NRF52_INPLACE_MEMORY, segment = NRF52_SEGMENT) {
    if (!segment || memory % segment) throw new Error('in-place memory must be a multiple of the segment size');
    const shift = Math.max((Math.ceil(memory / segment) - Math.ceil(from.length / segment)) * segment, 2 * segment);
    if (to.length > memory) throw new Error('new firmware does not fit the in-place window');
    const fromData = from.subarray(0, Math.min(from.length, memory - shift)), parts = [];
    for (let o = 0; o < to.length; o += segment) {
      const fo = Math.max(o + segment - shift, 0);
      parts.push(controlData(fo < fromData.length ? fromData.subarray(fo) : new Uint8Array(0), to.subarray(o, o + segment)));
    }
    const head = [Uint8Array.of(0x12), dep.pack.packSize(memory), dep.pack.packSize(segment), dep.pack.packSize(shift),
      dep.pack.packSize(from.length), dep.pack.packSize(to.length)];
    return concat(to.length ? [...head, dep.crle.compress(concat(parts))] : head);
  }

  // ---- LZMA wrapper (codec 3; motalib.lzma_wrap, motatool lzma.rs, firmware OtaLzma.h) ----------------------
  // "LZMA alone" around the detools CRLE patch: lc=0 lp=0 pb=0, 4 KB dictionary, the real size in the header.
  // LZMA-JS and liblzma produce different (equally valid) bytes; both unwrap to the same patch.
  const LZMA_MODE = { s: 12, f: 64, m: 1, lc: 0, lp: 0, pb: 0 };
  function lzmaWrap(patch) {
    if (!dep.lzma) throw new Error('LZMA encoder not loaded');
    return Uint8Array.from(dep.lzma.compress(patch, LZMA_MODE), (b) => b & 255);
  }

  // ---- merkle (sha2-256:8, promote-odd; motalib.merkle_root) -----------------------------------------------
  async function leafHashes(payload, bs = BLOCK_SIZE) {
    const out = [];
    for (let i = 0; i < payload.length; i += bs) out.push(await mh(payload.subarray(i, i + bs), HASH_LEN));
    return out;
  }
  async function merkleRoot(leaves) {
    if (!leaves.length) throw new Error('empty payload');
    let level = leaves;
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2)
        next.push(i + 1 < level.length ? await mh(concat([level[i], level[i + 1]]), HASH_LEN) : level[i]);
      level = next;
    }
    return level[0];
  }

  // ---- signing key ----------------------------------------------------------------------------------------
  /** A motatool key file: 64 hex chars (optionally with whitespace) or the raw 32-byte seed. */
  function parseSeed(input) {
    if (input instanceof Uint8Array && input.length === 32) return input;
    const text = input instanceof Uint8Array ? new TextDecoder().decode(input) : String(input);
    const seed = fromHex(text.replace(/\s+/g, ''));
    if (seed.length !== 32) throw new Error('signing key must be 32 bytes (64 hex chars, from `motatool keygen`)');
    return seed;
  }
  const publicKey = async (seed) => new Uint8Array(await dep.ed.getPublicKeyAsync(seed));

  // ---- build ----------------------------------------------------------------------------------------------
  /**
   * Build a v3 `.mota`.
   *   image     : new firmware (flat; EndF required — it names the target and version)
   *   base      : the target's RUNNING firmware (flat, EndF) for a delta, or null for a full image
   *   patchType : 'sequential' (ESP32 A/B) | 'in-place' (nRF52 OTAFIX bootloader)
   *   seed      : 32-byte Ed25519 seed, or null for unsigned (a nudge only acts on signed packages)
   *   encode    : optional async (kind, from, to) => patch, e.g. offloaded to a Web Worker
   */
  // compress (sequential deltas): 'auto' = the smaller of CRLE and LZMA (codec 3, needs firmware with LZMA
  // support), 'crle' = plain patch (any OTA firmware), 'lzma' = always wrap. In-place deltas stay CRLE (the nRF52
  // bootloader decodes them). `wrap` may be given to run the LZMA step elsewhere (Web Worker).
  async function buildMota({ image, base = null, patchType = 'sequential', seed = null, encode = null, force = false,
    compress = 'auto', wrap = null }) {
    const ident = await parseEndF(image);
    if (!ident) throw new Error('new firmware has no valid EndF trailer — build it with ENABLE_OTA (tools/mota/pio_endf.py)');
    let codec = CODEC.FULL, payload = image, baseHash = new Uint8Array(8);
    if (base) {
      const b = await parseEndF(base);
      if (!b) throw new Error('installed firmware has no valid EndF trailer — it must be the exact image running on the node');
      if (!force && b.hwId !== ident.hwId) throw new Error(`installed firmware is for "${b.hwId}", new firmware for "${ident.hwId}"`);
      if (equal(b.bodyHash, ident.bodyHash)) throw new Error('installed and new firmware are identical');
      codec = patchType === 'in-place' ? CODEC.INPLACE : CODEC.SEQUENTIAL;
      const run = encode || (async (k, f, t) => (k === 'in-place' ? encodeInPlace(f, t) : encodeSequential(f, t)));
      payload = await run(patchType, base, image);
      if (codec === CODEC.SEQUENTIAL && compress !== 'crle') {
        const wrapped = await (wrap || (async (p) => lzmaWrap(p)))(payload);
        if (compress === 'lzma' || wrapped.length < payload.length) { payload = wrapped; codec = CODEC.SEQUENTIAL_LZMA; }
      }
      baseHash = b.bodyHash;
    }
    const leaves = await leafHashes(payload);
    if (leaves.length < 1 || leaves.length > 0xffff) throw new Error('payload yields an invalid block count');
    const mf = new Uint8Array(MFL);
    mf[OFF.FORMAT_VER] = FORMAT_VER;
    mf[OFF.FLAGS] = (codec === CODEC.FULL ? FLAG_FULL : 0) | (seed ? FLAG_SIGNED : 0);
    mf[OFF.HASH_ALGO] = HASH_ALGO_SHA256;
    wrU32(mf, OFF.TARGET_ID, ident.targetId);
    wrU32(mf, OFF.FW_VERSION, ident.fwVersion);
    wrU32(mf, OFF.IMAGE_SIZE, image.length);
    wrU32(mf, OFF.PAYLOAD_SIZE, payload.length);
    mf[OFF.BLOCK_SIZE_LOG2] = 10;
    mf.set(await merkleRoot(leaves), OFF.MERKLE_ROOT);
    mf.set(await sha256(image), OFF.IMAGE_HASH);
    mf.set(await sha256(payload), OFF.PAYLOAD_HASH);
    mf[OFF.CODEC_ID] = codec;
    const hw = new TextEncoder().encode(ident.hwId).subarray(0, 32);
    mf.set(hw, OFF.HW_ID);
    mf.set(baseHash, OFF.BASE_HASH);
    if (seed) {
      mf.set(await publicKey(seed), OFF.SIGNER);
      mf.set(new Uint8Array(await dep.ed.signAsync(mf.subarray(0, SIGNED_LEN), seed)), OFF.SIGNATURE);
    }
    mf.set([0xff, 0xff, 0xff, 0xff], OFF.APPROVAL);
    const total = HEADER_LEN + MFL + leaves.length * HASH_LEN + payload.length + TRAILER.length;
    const bytes = concat([MAGIC, u32le(total), mf, ...leaves, payload, TRAILER]);
    return { bytes, manifest: parseMota(bytes), ident };
  }

  /** Parse (and structurally check) a `.mota`; throws on anything the firmware would reject outright. */
  function parseMota(bytes) {
    if (bytes.length < HEADER_LEN + MFL + TRAILER.length || !equal(bytes.subarray(0, 4), MAGIC))
      throw new Error('not a .mota file');
    if (rdU32(bytes, 4) !== bytes.length) throw new Error('.mota size field does not match the file');
    if (!equal(bytes.subarray(bytes.length - 5), TRAILER)) throw new Error('.mota trailer missing');
    const mf = bytes.subarray(HEADER_LEN, HEADER_LEN + MFL);
    if (mf[OFF.FORMAT_VER] !== FORMAT_VER)
      throw new Error(`.mota format v${mf[OFF.FORMAT_VER]}; this page and current firmware need v${FORMAT_VER} (rebuild it)`);
    const payloadSize = rdU32(mf, OFF.PAYLOAD_SIZE), blockCount = Math.ceil(payloadSize / (1 << mf[OFF.BLOCK_SIZE_LOG2]));
    const leavesOff = HEADER_LEN + MFL, payloadOff = leavesOff + blockCount * HASH_LEN;
    if (payloadOff + payloadSize + TRAILER.length !== bytes.length) throw new Error('.mota geometry is inconsistent');
    let hw = mf.subarray(OFF.HW_ID, OFF.HW_ID + 32); const z = hw.indexOf(0); if (z >= 0) hw = hw.subarray(0, z);
    return {
      flags: mf[OFF.FLAGS], signed: !!(mf[OFF.FLAGS] & FLAG_SIGNED), full: !!(mf[OFF.FLAGS] & FLAG_FULL),
      targetId: rdU32(mf, OFF.TARGET_ID), fwVersion: rdU32(mf, OFF.FW_VERSION), imageSize: rdU32(mf, OFF.IMAGE_SIZE),
      payloadSize, blockCount, codec: mf[OFF.CODEC_ID], hwId: String.fromCharCode(...hw),
      merkleRoot: mf.slice(OFF.MERKLE_ROOT, OFF.MERKLE_ROOT + HASH_LEN), mid: mf.slice(OFF.MERKLE_ROOT, OFF.MERKLE_ROOT + 4),
      baseHash: mf.slice(OFF.BASE_HASH, OFF.BASE_HASH + 8), signer: mf.slice(OFF.SIGNER, OFF.SIGNER + 32),
      leavesOff, payloadOff, total: bytes.length,
    };
  }

  /** Full self-check of a container: leaves, root, payload hash, signature (as `motatool verify`). */
  async function verifyMota(bytes) {
    const m = parseMota(bytes), problems = [];
    const payload = bytes.subarray(m.payloadOff, m.payloadOff + m.payloadSize);
    const leaves = await leafHashes(payload, 1 << bytes[HEADER_LEN + OFF.BLOCK_SIZE_LOG2]);
    for (let i = 0; i < leaves.length; i++)
      if (!equal(leaves[i], bytes.subarray(m.leavesOff + i * HASH_LEN, m.leavesOff + (i + 1) * HASH_LEN))) { problems.push(`leaf ${i} mismatch`); break; }
    if (!equal(await merkleRoot(leaves), m.merkleRoot)) problems.push('merkle_root mismatch');
    if (!equal(await sha256(payload), bytes.subarray(HEADER_LEN + OFF.PAYLOAD_HASH, HEADER_LEN + OFF.PAYLOAD_HASH + 32))) problems.push('payload_hash mismatch');
    if (m.signed) {
      const mf = bytes.subarray(HEADER_LEN, HEADER_LEN + MFL);
      const ok = await dep.ed.verifyAsync(mf.subarray(OFF.SIGNATURE, OFF.SIGNATURE + 64), mf.subarray(0, SIGNED_LEN), m.signer);
      if (!ok) problems.push('signature does not verify');
    }
    return problems;
  }

  /** The motatool auto-name: `<hw>_<target8>_v<ver>_<full|seqdelta|ipdelta>_<mid8>.mota`. */
  function suggestedName(m) {
    const kind = m.codec === CODEC.FULL ? 'full' : m.codec === CODEC.SEQUENTIAL ? 'seqdelta'
      : m.codec === CODEC.SEQUENTIAL_LZMA ? 'seqlzdelta' : 'ipdelta';
    const hw = (m.hwId || 'fw').replace(/[^A-Za-z0-9_.-]/g, '_');
    return `${hw}_${m.targetId.toString(16).toUpperCase().padStart(8, '0')}_v${versionStr(m.fwVersion)}_${kind}_${toHex(m.mid)}.mota`;
  }

  // ---- seeder (host side of MotaSeederProto.h; mirrors motatool serve.rs SeederCore) -----------------------
  function describe(bytes, m) {
    const w = new Uint8Array(SEEDER.DESC_WIRE);
    w.set(m.mid, 0); wrU32(w, 4, m.targetId); wrU32(w, 8, m.fwVersion); w[12] = m.codec; w[13] = m.flags;
    wrU32(w, 14, bytes.length); wrU32(w, 18, m.leavesOff); wrU32(w, 22, m.blockCount);
    wrU32(w, 26, m.payloadOff); wrU32(w, 30, m.payloadSize);
    return w;
  }
  /** Serve-only seeder over a list of `.mota` byte arrays. handle() -> [status, payload] or null to ignore. */
  class SeederCore {
    constructor(motas) { this.items = motas.map((b) => ({ bytes: b, m: parseMota(b) })); }
    handle(op, args) {
      const S = SEEDER;
      if (op === S.OP_COUNT) return [S.OK, Uint8Array.of(Math.min(this.items.length, 255))];
      if (op === S.OP_DESCRIBE) { const it = this.items[args[0]]; return it ? [S.OK, describe(it.bytes, it.m)] : [S.ERR, new Uint8Array(0)]; }
      if (op === S.OP_READ) {
        const it = this.items[args[0]], off = rdU32(args, 1), len = args[5] | (args[6] << 8);
        return it && off + len <= it.bytes.length ? [S.OK, it.bytes.slice(off, off + len)] : [S.ERR, new Uint8Array(0)];
      }
      if (op >= S.OP_STAT && op <= S.OP_FIN) return [S.ERR, new Uint8Array(0)];   // no pull-to-folder capture here
      return null;
    }
  }
  function requestHeaderLen(op) {
    const S = SEEDER;
    return op === S.OP_COUNT ? 0 : op === S.OP_DESCRIBE ? 1 : op === S.OP_READ ? 7
      : (op === S.OP_STAT || op === S.OP_FIN) ? 4 : op === S.OP_BEGIN ? 8 : (op === S.OP_SREAD || op === S.OP_WRITE) ? 10 : -1;
  }
  function encodeResponse(op, status, payload) {
    const f = new Uint8Array(5 + payload.length);
    f[0] = SEEDER.RSP0; f[1] = SEEDER.RSP1; f[2] = op; f[3] = status; f.set(payload, 4);
    let x = 0; for (let i = 0; i < f.length - 1; i++) x ^= f[i];
    f[f.length - 1] = x;
    return f;
  }
  /**
   * Byte-stream demultiplexer for the shared serial wire: seeder requests (`M S op args xsum`) and the node's
   * console text. Same resync rule as motatool serve_loop: a request starts where `M` is followed by `S`.
   * feed() returns events [{type:'req', op, args}] / [{type:'line', text}] / [{type:'bad'}].
   */
  class WireParser {
    // Only an 'M' is held back (it may start "M S"); every other byte is handled at once, so a console line
    // is emitted the moment its '\n' arrives (holding the previous byte delayed each reply by one line).
    constructor() { this.held = false; this.line = ''; this.frame = null; }
    get inFrame() { return this.frame !== null; }
    text(c, ev) {
      if (c === 10 || this.line.length > 512) {
        const t = this.line.replace(/\r$/, ''); if (t.trim()) ev.push({ type: 'line', text: t }); this.line = '';
        if (c === 10) return;
      }
      this.line += String.fromCharCode(c);
    }
    feed(chunk) {
      const ev = [];
      for (const b of chunk) {
        const f = this.frame;
        if (f) {
          f.buf.push(b);
          if (f.need < 0) {                                          // first byte = op
            const h = requestHeaderLen(b);
            if (h < 0) { this.frame = null; ev.push({ type: 'bad' }); continue; }
            f.op = b; f.need = h + 1; f.buf = [];                    // header + xsum (WRITE: + data, below)
            continue;
          }
          if (f.op === SEEDER.OP_WRITE && !f.dataKnown && f.buf.length === 10) {
            const dlen = f.buf[8] | (f.buf[9] << 8);
            if (dlen > SEEDER.WRITE_MAX) { this.frame = null; ev.push({ type: 'bad' }); continue; }
            f.need += dlen; f.dataKnown = true;
          }
          if (f.buf.length === f.need) {
            const args = Uint8Array.from(f.buf.slice(0, -1)); let x = f.op; for (const v of args) x ^= v;
            this.frame = null;
            ev.push(x === f.buf[f.buf.length - 1] ? { type: 'req', op: f.op, args } : { type: 'bad' });
          }
          continue;
        }
        if (this.held) {
          this.held = false;
          if (b === SEEDER.REQ1) { this.frame = { op: -1, need: -1, buf: [], dataKnown: false }; continue; }
          this.text(SEEDER.REQ0, ev);
        }
        if (b === SEEDER.REQ0) { this.held = true; continue; }
        this.text(b, ev);
      }
      return ev;
    }
  }

  // ---- method A: nudge scheduling (motatool nudge.rs, plus console confirmation) ---------------------------
  function parseTargets(text) {
    const out = [], seen = new Set();
    for (const raw of String(text).split(/[\s,;]+/)) {
      const k = raw.trim().toUpperCase();
      if (!k) continue;
      if (!/^[0-9A-F]+$/.test(k) || k.length < 2 * NUDGE_PREFIX || k.length > 64)
        throw new Error(`"${raw}": expected a node public key in hex (at least ${2 * NUDGE_PREFIX} chars)`);
      const p = k.slice(0, 2 * NUDGE_PREFIX);
      if (!seen.has(p)) { seen.add(p); out.push(p); }
    }
    return out;
  }
  /**
   * Re-send schedule. A nudge is one unacknowledged flood, so it is repeated every `retryMs` until the swarm
   * visibly fetches the package (the node READs payload blocks from us) or `maxTries` is spent. A send only
   * counts once the node's console confirms it (`OK nudged <prefix>`): a line written while the node was
   * itself waiting on a seeder reply can be swallowed, so an unconfirmed send is retried after `confirmMs`.
   */
  class Nudger {
    constructor({ prefixes, mid, install = true, payloadOff, retryMs = 120000, maxTries = 5, confirmMs = 6000,
      catalogGraceMs = 8000, gapMs = 2000, now = 0 }) {
      this.t = prefixes.map((p) => ({ prefix: p, sent: 0, confirmed: 0, pendingAt: null, nextAt: 0 }));
      Object.assign(this, { mid, install, payloadOff, retryMs, maxTries, confirmMs, catalogGraceMs, gapMs });
      this.started = now; this.catalogSeen = false; this.fetching = false; this.lineAt = -Infinity;
    }
    command(t) { return `ota nudge ${t.prefix} ${toHex(this.mid)}${this.install ? '' : ' fetch'}`; }
    done(t) { return this.fetching || t.confirmed >= this.maxTries || t.sent >= this.maxTries + 3; }
    get finished() { return this.t.every((t) => this.done(t)); }
    /** Feed seeder requests. Returns a note when the first block fetch is seen. */
    onRequest(op, args) {
      if (op === SEEDER.OP_DESCRIBE) this.catalogSeen = true;
      if (op === SEEDER.OP_READ && args[0] === 0 && rdU32(args, 1) >= this.payloadOff && !this.fetching) {
        this.fetching = true; return 'the mesh is fetching blocks of this update — nudging stopped';
      }
      return null;
    }
    /** Feed console lines from the node. */
    onLine(text, now) {
      const m = /nudged\s+([0-9A-Fa-f]{12})/.exec(text);
      if (!m) return;
      const t = this.t.find((x) => x.prefix === m[1].toUpperCase() && x.pendingAt !== null);
      if (t) { t.confirmed++; t.pendingAt = null; t.nextAt = now + this.retryMs; }
    }
    /** The next console line to write now, or null. */
    poll(now) {
      if (!this.catalogSeen && now - this.started < this.catalogGraceMs) return null;
      if (now - this.lineAt < this.gapMs) return null;
      for (const t of this.t) {
        if (this.done(t)) continue;
        if (t.pendingAt !== null && now - t.pendingAt < this.confirmMs) continue;   // waiting for "OK nudged"
        if (t.pendingAt === null && now < t.nextAt) continue;
        t.sent++; t.pendingAt = now; this.lineAt = now;
        return this.command(t);
      }
      return null;
    }
  }

  /**
   * Hand the package over to the USB node (`ota host <mid>`): the node copies the .mota from this page into its
   * own flash (sequential seeder READs), verifies it, serves it to the mesh as its origin and sends the nudges
   * itself (`ota host nudge <prefix>`), so the computer can be disconnected afterwards. The page only writes a
   * console line when the seeder traffic is quiet, so progress during the copy comes from the READs it answers.
   * States: start -> sent -> importing -> hosting (queue the nudge lines) -> done | failed.
   */
  class Handover {
    constructor({ mid, total, prefixes = [], install = true, pollMs = 3000, stallMs = 60000, startTries = 3,
      confirmMs = 6000, nudgeTries = 3, now = 0 }) {
      Object.assign(this, { mid, total, install, pollMs, stallMs, startTries, confirmMs, nudgeTries });
      this.midHex = toHex(mid); this.state = 'start'; this.copied = 0; this.tries = 0; this.error = null;
      this.lastActivity = now; this.nextPoll = now;
      this.t = prefixes.map((p) => ({ prefix: p, confirmed: false, sentAt: null, tries: 0 }));
    }
    get pct() { return this.total ? Math.min(100, Math.floor(100 * this.copied / this.total)) : 0; }
    get finished() { return this.state === 'done' || this.state === 'failed'; }
    fail(text) { this.state = 'failed'; this.error = text; return { level: 'err', text }; }
    /** Seeder READ of [off, off+len) answered by the page (the node copying the package). */
    onRead(off, len, now) {
      if (this.state !== 'sent' && this.state !== 'importing') return;
      this.state = 'importing'; this.copied = Math.max(this.copied, off + len); this.lastActivity = now;
    }
    /** The next console line to write (call only while the link is quiet), or null. */
    poll(now) {
      if (this.state === 'start') {
        this.tries++; this.state = 'sent'; this.lastActivity = now; this.nextPoll = now + this.pollMs;
        return `ota host ${this.midHex}`;
      }
      if (this.state === 'sent' || this.state === 'importing') {
        if (now - this.lastActivity > this.stallMs) { this.fail('The USB node stopped copying the update.'); return null; }
        if (now >= this.nextPoll) { this.nextPoll = now + this.pollMs; return 'ota host'; }
        return null;
      }
      if (this.state === 'hosting') {
        for (const t of this.t) {
          if (t.confirmed || t.tries >= this.nudgeTries) continue;
          if (t.sentAt !== null && now - t.sentAt < this.confirmMs) return null;   // wait for "OK this node nudges"
          t.tries++; t.sentAt = now;
          return `ota host nudge ${t.prefix}${this.install ? '' : ' fetch'}`;
        }
        this.state = 'done';
      }
      return null;
    }
    /** Feed console lines from the node; returns a note for the log, or null. */
    onLine(text, now) {
      let m;
      const early = this.state === 'sent' || this.state === 'importing';
      if (this.state === 'sent' && /Unknown OTA command/.test(text))
        return this.fail('This node\'s firmware cannot host updates (no `ota host`). Update it first, or keep the page open and use Send update request.');
      if ((m = /OK importing mid=([0-9A-F]{8})/i.exec(text)) && m[1].toUpperCase() === this.midHex) {
        if (this.state === 'sent') this.state = 'importing';
        this.lastActivity = now;
        return { level: 'info', text: 'The USB node is copying the update into its own flash.' };
      }
      if ((m = /host: importing mid=([0-9A-F]{8}) (\d+)\/(\d+) B/i.exec(text)) && m[1].toUpperCase() === this.midHex) {
        this.state = 'importing'; this.copied = Math.max(this.copied, +m[2]); this.lastActivity = now; return null;
      }
      if ((m = /host: serving mid=([0-9A-F]{8})/i.exec(text)) && m[1].toUpperCase() === this.midHex) {
        if (!early) return null;
        this.state = 'hosting'; this.copied = this.total;
        return { level: 'ok', text: 'The USB node has verified the update and serves it to the mesh itself.' };
      }
      if (early && (m = /host: not hosting \(last mid=[0-9A-F]{8}: ([^)]*)\)/i.exec(text)))
        return this.fail(`The USB node gave up: ${m[1]}.`);
      if (this.state === 'sent' && /host: not hosting\./.test(text)) {   // our `ota host <mid>` line was lost
        if (this.tries < this.startTries) { this.state = 'start'; return null; }
        return this.fail('The USB node did not start copying the update.');
      }
      if (early && (m = /-> ERR (.*)/.exec(text))) return this.fail(`The USB node refused: ${m[1].trim()}`);
      if ((m = /OK this node nudges ([0-9A-F]{12})/i.exec(text))) {
        const t = this.t.find((x) => x.prefix === m[1].toUpperCase());
        if (t) t.confirmed = true;
      }
      return null;
    }
  }

  // ---- airtime estimate (rough planning aid) ----------------------------------------------------------------
  /** OTA_DATA packets for a payload: 171-byte fragments, 6 per 1 KB block (OTA_FRAG_DATA). */
  const dataPackets = (payloadSize) => Math.ceil(payloadSize / BLOCK_SIZE) * Math.ceil(BLOCK_SIZE / 171);

  const api = {
    init, CODEC, SEEDER, FORMAT_VER, HASH_LEN, MFL, NUDGE_PREFIX, NRF52_INPLACE_MEMORY, NRF52_MAX_INPLACE_MOTA,
    toHex, fromHex, parseIntelHex, parseUf2, parseDfuZip, unzipEntry, cutAtEndF, parseEndF, versionStr, encodeSequential, encodeInPlace, lzmaWrap, leafHashes, merkleRoot,
    parseSeed, publicKey, buildMota, parseMota, verifyMota, suggestedName, SeederCore, encodeResponse, WireParser,
    parseTargets, Nudger, Handover, dataPackets, sha256,
  };
  return api;
});
