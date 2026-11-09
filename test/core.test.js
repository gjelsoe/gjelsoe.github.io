// Node test of src/mota_core.js against motatool/motalib-built references.
//   node tools/mota/web/test/core.test.js <fixture-dir>
// Fixture dir: esp_old.bin esp_new.bin nrf_old.bin nrf_new.bin key.hex mt_full.mota mt_seq.mota mt_ip.mota
// (see tools/mota/web/test/make_fixtures.sh). Writes js_*.mota there for the Python/C++ cross-checks.
'use strict';
const fs = require('fs'), path = require('path'), vm = require('vm'), assert = require('assert');
const W = path.join(__dirname, '..');
vm.runInThisContext(fs.readFileSync(path.join(W, 'dist', 'noble-ed25519.global.js'), 'utf8'));
const C = require(path.join(W, 'src', 'mota_core.js')).init({
  bsdiff: require(path.join(W, 'vendor/detools-js/bsdiff.js')),
  pack: require(path.join(W, 'vendor/detools-js/pack-size.js')),
  crle: require(path.join(W, 'vendor/detools-js/crle.js')),
  ed: globalThis.nobleEd25519, subtle: globalThis.crypto.subtle,
  lzma: require(path.join(W, 'vendor/lzma-js/lzma-c.js')),
});
const D = process.argv[2];
const rd = (n) => new Uint8Array(fs.readFileSync(path.join(D, n)));
const eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
let fails = 0;
async function t(name, fn) {
  try { await fn(); console.log('ok   ', name); } catch (e) { fails++; console.log('FAIL ', name, '\n     ', e.message); }
}

(async () => {
  const seed = C.parseSeed(fs.readFileSync(path.join(D, 'key.hex'), 'utf8'));

  await t('full signed .mota is byte-identical to motatool', async () => {
    const { bytes } = await C.buildMota({ image: rd('esp_new.bin'), seed });
    fs.writeFileSync(path.join(D, 'js_full.mota'), bytes);
    assert(eq(bytes, rd('mt_full.mota')), 'differs from mt_full.mota');
  });
  await t('sequential delta (ESP32) is byte-identical to motatool', async () => {
    const { bytes, manifest: m } = await C.buildMota({ image: rd('esp_new.bin'), base: rd('esp_old.bin'), patchType: 'sequential', seed, compress: 'crle' });
    fs.writeFileSync(path.join(D, 'js_seq.mota'), bytes);
    const r = C.parseMota(rd('mt_seq.mota'));
    for (const k of ['codec', 'targetId', 'fwVersion', 'imageSize', 'hwId', 'flags']) assert.strictEqual(m[k], r[k], k);
    assert(eq(m.baseHash, r.baseHash), 'base_hash');
    assert(eq(bytes, rd('mt_seq.mota')), 'sequential delta differs from motatool');
  });
  await t('in-place delta (nRF52) is byte-identical to motatool', async () => {
    const t0 = Date.now();
    const { bytes, manifest: m } = await C.buildMota({ image: rd('nrf_new.bin'), base: rd('nrf_old.bin'), patchType: 'in-place', seed });
    fs.writeFileSync(path.join(D, 'js_ip.mota'), bytes);
    const r = C.parseMota(rd('mt_ip.mota'));
    for (const k of ['codec', 'targetId', 'fwVersion', 'imageSize', 'hwId', 'flags']) assert.strictEqual(m[k], r[k], k);
    assert(eq(bytes, rd('mt_ip.mota')), 'in-place delta differs from motatool');
    console.log(`      in-place encode ${Date.now() - t0} ms`);
  });
  await t('auto compression: LZMA-wrapped codec 3 when smaller (unwrap checked in python + device C)', async () => {
    const { bytes, manifest: m } = await C.buildMota({ image: rd('esp_new.bin'), base: rd('esp_old.bin'), patchType: 'sequential', seed });
    fs.writeFileSync(path.join(D, 'js_seq_lzma.mota'), bytes);
    assert.strictEqual(m.codec, C.CODEC.SEQUENTIAL_LZMA);
    const crle = C.parseMota(rd('mt_seq.mota'));
    assert(m.payloadSize < crle.payloadSize / 2, `LZMA ${m.payloadSize} vs CRLE ${crle.payloadSize}`);
    const p = bytes.subarray(m.payloadOff, m.payloadOff + m.payloadSize);
    assert.strictEqual(p[0], 0);                                                   // lc0 lp0 pb0
    assert.strictEqual(p[1] | p[2] << 8 | p[3] << 16 | p[4] << 24, 4096);          // 4 KB dictionary
    assert.strictEqual(p[5] | p[6] << 8 | p[7] << 16 | p[8] << 24, crle.payloadSize); // real size
    assert.deepStrictEqual(await C.verifyMota(bytes), []);
    assert(/seqlzdelta/.test(C.suggestedName(m)));
    // in-place stays CRLE whatever is asked
    const ip = await C.buildMota({ image: rd('nrf_new.bin'), base: rd('nrf_old.bin'), patchType: 'in-place', seed });
    assert.strictEqual(ip.manifest.codec, C.CODEC.INPLACE);
  });
  await t('verifyMota accepts our output and motatool output, rejects tampering', async () => {
    for (const n of ['js_full.mota', 'js_seq.mota', 'js_ip.mota', 'mt_seq.mota']) assert.deepStrictEqual(await C.verifyMota(rd(n)), [], n);
    const bad = rd('js_seq.mota'); bad[bad.length - 100] ^= 1;
    assert((await C.verifyMota(bad)).length > 0, 'payload flip not detected');
    const bad2 = rd('js_seq.mota'); bad2[8 + 3] ^= 1;   // target_id inside the signed region
    assert((await C.verifyMota(bad2)).some((p) => /signature/.test(p)), 'signed-field flip not detected');
  });
  await t('identity / safety checks', async () => {
    await assert.rejects(C.buildMota({ image: rd('esp_new.bin').slice(0, -1) }), /EndF/);
    await assert.rejects(C.buildMota({ image: rd('esp_new.bin'), base: rd('nrf_old.bin') }), /RAK4631/);
    await assert.rejects(C.buildMota({ image: rd('esp_new.bin'), base: rd('esp_new.bin') }), /identical/);
    const v2 = rd('js_full.mota'); v2[8] = 2;
    assert.throws(() => C.parseMota(v2), /format v2/);
  });
  await t('Intel HEX flattening (gaps 0xFF, extended linear address)', async () => {
    const hex = [':020000040002F8', ':04000000DEADBEEFC4', ':02000800AABB91', ':00000001FF'].join('\n');
    const img = C.parseIntelHex(hex);
    assert(eq(img, Uint8Array.of(0xde, 0xad, 0xbe, 0xef, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xbb)), C.toHex(img));
    assert.throws(() => C.parseIntelHex(':04000000DEADBEEFC5\n:00000001FF'), /checksum/);
  });
  await t('seeder: COUNT / DESCRIBE / READ / storage refused', async () => {
    const mota = rd('js_seq.mota'), m = C.parseMota(mota), core = new C.SeederCore([mota]), S = C.SEEDER;
    assert.deepStrictEqual(Array.from(core.handle(S.OP_COUNT, new Uint8Array(0))[1]), [1]);
    const [st, d] = core.handle(S.OP_DESCRIBE, Uint8Array.of(0));
    assert.strictEqual(st, S.OK); assert.strictEqual(d.length, 38);
    assert(eq(d.subarray(0, 4), m.mid));
    const u32 = (o) => d[o] | (d[o + 1] << 8) | (d[o + 2] << 16) | (d[o + 3] << 24);
    assert.strictEqual(u32(14), mota.length); assert.strictEqual(u32(18), m.leavesOff);
    assert.strictEqual(u32(22), m.blockCount); assert.strictEqual(u32(26), m.payloadOff); assert.strictEqual(u32(30), m.payloadSize);
    assert.strictEqual(core.handle(S.OP_DESCRIBE, Uint8Array.of(1))[0], S.ERR);
    const rq = Uint8Array.of(0, 0x10, 0, 0, 0, 0x40, 0);           // idx0 off 16 len 64
    assert(eq(core.handle(S.OP_READ, rq)[1], mota.subarray(16, 80)));
    const past = Uint8Array.of(0, ...[mota.length & 255, (mota.length >> 8) & 255, (mota.length >> 16) & 255, 0], 1, 0);
    assert.strictEqual(core.handle(S.OP_READ, past)[0], S.ERR);
    assert.strictEqual(core.handle(S.OP_BEGIN, new Uint8Array(8))[0], S.ERR);
    assert.strictEqual(core.handle(0x55, new Uint8Array(0)), null);
  });
  await t('wire parser: frames between console text, bad xsum, split chunks', async () => {
    const enc = (s) => new TextEncoder().encode(s);
    const p = new C.WireParser();
    const req = Uint8Array.of(0x4d, 0x53, 3, 0, 1, 2, 3, 4, 5, 6, 3 ^ 0 ^ 1 ^ 2 ^ 3 ^ 4 ^ 5 ^ 6);
    const all = [...enc('  -> OK folder on\r\n'), ...req, ...enc('Mesh hello\r\n'), 0x4d, 0x53, 1, 0x00 /*bad*/, ...enc('x\n')];
    const ev = [];
    for (let i = 0; i < all.length; i += 3) ev.push(...p.feed(Uint8Array.from(all.slice(i, i + 3))));
    assert.deepStrictEqual(ev.filter((e) => e.type === 'line').map((e) => e.text), ['  -> OK folder on', 'Mesh hello', 'x']);   // the last line too (old parser held it back)
    const r = ev.find((e) => e.type === 'req');
    assert.strictEqual(r.op, 3); assert.deepStrictEqual(Array.from(r.args), [0, 1, 2, 3, 4, 5, 6]);
    assert(ev.some((e) => e.type === 'bad'));
    // a reply line is emitted as soon as its newline arrives — no extra byte needed (hardware bug report)
    const p2 = new C.WireParser();
    assert.deepStrictEqual(p2.feed(enc('  -> OTA | this fw 39316808\r\n')).map((e) => e.text), ['  -> OTA | this fw 39316808']);
    assert.deepStrictEqual(p2.feed(enc('More text\n')).map((e) => e.text), ['More text']);   // 'M' at line start
    assert.deepStrictEqual(p2.feed(enc('M')), []);                                            // held: may start "MS"
    assert.deepStrictEqual(p2.feed(enc('x\n')).map((e) => e.text), ['Mx']);
    const f = C.encodeResponse(1, 0, Uint8Array.of(1));
    assert.deepStrictEqual(Array.from(f), [0x6d, 0x73, 1, 0, 1, 0x6d ^ 0x73 ^ 1 ^ 0 ^ 1]);
  });
  await t('nudger: waits for catalogue, needs console confirmation, retries, stops on fetch', async () => {
    const mota = rd('js_seq.mota'), m = C.parseMota(mota), S = C.SEEDER;
    const n = new C.Nudger({ prefixes: C.parseTargets('693FAE0783D124C3 aabbccddeeff'), mid: m.mid, payloadOff: m.payloadOff,
      retryMs: 60000, maxTries: 2, confirmMs: 5000, gapMs: 2000, now: 0 });
    assert.strictEqual(n.poll(0), null);                                      // node hasn't read the catalogue yet
    n.onRequest(S.OP_DESCRIBE, Uint8Array.of(0));
    assert.strictEqual(n.poll(0), `ota nudge 693FAE0783D1 ${C.toHex(m.mid)}`);
    assert.strictEqual(n.poll(1000), null);                                   // line gap
    assert(/AABBCCDDEEFF/.test(n.poll(2500)));
    n.onLine(`  -> OK nudged 693FAE0783D1 -> mid=${C.toHex(m.mid)} (fetch+install).`, 3000);
    assert.strictEqual(n.poll(5000), null);                                   // first confirmed, second still pending
    assert(/AABBCCDDEEFF/.test(n.poll(8000)), 'unconfirmed send retried after confirmMs');
    assert(/693FAE0783D1/.test(n.poll(63500)), 'confirmed one re-sent after retryMs');
    const pl = Uint8Array.of(0, ...[m.payloadOff & 255, (m.payloadOff >> 8) & 255, 0, 0], 64, 0);
    assert.strictEqual(n.onRequest(S.OP_READ, Uint8Array.of(0, 8, 0, 0, 0, 64, 0)), null);   // header read: not a fetch
    assert(n.onRequest(S.OP_READ, pl)); assert(n.finished); assert.strictEqual(n.poll(1e9), null);
    assert.throws(() => C.parseTargets('693FAE0783'), /at least 12/);
  });
  await t('handover: host command, copy progress, verified, then the node takes the nudges', async () => {
    const mota = rd('js_seq.mota'), m = C.parseMota(mota), mid = C.toHex(m.mid);
    const h = new C.Handover({ mid: m.mid, total: mota.length, prefixes: C.parseTargets('693FAE0783D124C3 aabbccddeeff'),
      install: false, pollMs: 3000, stallMs: 60000, confirmMs: 5000, now: 0 });
    assert.strictEqual(h.poll(0), `ota host ${mid}`);
    assert.strictEqual(h.poll(100), null);
    assert.deepStrictEqual(h.onLine(`  -> OK importing mid=${mid} (${mota.length} B) from the folder`, 200).level, 'info');
    h.onRead(0, 241, 300); h.onRead(241, mota.length - 241 - 1000, 400);
    assert.strictEqual(h.state, 'importing'); assert(h.pct > 0 && h.pct < 100);
    assert.strictEqual(h.poll(3100), 'ota host');                              // status poll once quiet
    h.onLine(`  -> host: importing mid=${mid} 9/${mota.length} B (1%) from the folder`, 3200);   // stale: progress kept
    assert(h.pct > 1);
    assert.strictEqual(h.onLine(`  -> host: serving mid=${mid} (60 blocks)`, 3300).level, 'ok');
    assert.strictEqual(h.poll(3400), 'ota host nudge 693FAE0783D1 fetch');
    assert.strictEqual(h.poll(4000), null);                                   // waits for the confirmation
    h.onLine('  -> OK this node nudges 693FAE0783D1 (fetch) up to 5 times, 120s apart, once it is hosting', 4100);
    assert.strictEqual(h.poll(4200), 'ota host nudge AABBCCDDEEFF fetch');
    assert.strictEqual(h.poll(9300), 'ota host nudge AABBCCDDEEFF fetch');    // unconfirmed: sent again
    h.onLine('  -> OK this node nudges AABBCCDDEEFF (fetch) up to 5 times', 9400);
    assert.strictEqual(h.poll(9500), null); assert.strictEqual(h.state, 'done'); assert(h.finished);
    // refusals end it with the node's reason
    const r = new C.Handover({ mid: m.mid, total: mota.length, now: 0 }); r.poll(0);
    assert.strictEqual(r.onLine('  -> ERR not signed by a trusted key (`ota key add <signer>`)', 1).level, 'err');
    assert(r.finished && /trusted key/.test(r.error));
    const o = new C.Handover({ mid: m.mid, total: mota.length, now: 0 }); o.poll(0);
    o.onLine('  -> Unknown OTA command. Type `ota help`.', 1); assert(/cannot host/.test(o.error));
    const v = new C.Handover({ mid: m.mid, total: mota.length, now: 0 }); v.poll(0); v.onRead(0, 100, 10);
    v.onLine(`  -> host: not hosting (last mid=${mid}: verification failed)`, 20); assert(/verification failed/.test(v.error));
    // a lost start line is sent again; a stalled copy fails
    const l = new C.Handover({ mid: m.mid, total: mota.length, startTries: 2, now: 0 }); l.poll(0);
    l.onLine('  -> host: not hosting. `ota host <mid8>` keeps a .mota from the folder', 3000);
    assert.strictEqual(l.poll(3100), `ota host ${mid}`);
    l.onRead(0, 100, 3200); assert.strictEqual(l.poll(3200 + 61000), null); assert(/stopped copying/.test(l.error));
  });
  console.log(fails ? `\n${fails} FAILED` : '\nall passed');
  process.exit(fails ? 1 : 0);
})();
