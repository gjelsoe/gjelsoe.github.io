// End-to-end browser test of mota_push.html with a simulated node behind a fake Web Serial port.
//   node tools/mota/web/test/page.test.js <fixture-dir>
// The fake node speaks the device side of MotaSeederProto.h (COUNT, DESCRIBE, READ ...) after it sees
// `ota folder on`, and answers `ota nudge` like OtaCli.cpp. Checks: the page's download is byte-identical to
// motatool's .mota, every seeder reply is correct, the nudge line is well-formed and confirmed, and nudging
// stops once payload blocks are fetched.
'use strict';
const path = require('path'), fs = require('fs'), assert = require('assert');
const { chromium } = require('playwright');
const D = process.argv[2], PAGE = 'file://' + path.join(__dirname, '..', 'mota_push.html');

const FAKE_SERIAL = () => {
  const sim = window.__sim = { rx: [], lines: [], replies: [], problems: [], nudges: [], requests: 0 };
  let ctrl; const readable = new ReadableStream({ start(c) { ctrl = c; } });
  const send = (bytes) => ctrl.enqueue(Uint8Array.from(bytes));
  const sendText = (t) => send(new TextEncoder().encode(t));
  let text = '', pending = null, buf = [];
  const queue = [];
  function request(op, args, expectLen) {
    return new Promise((resolve) => queue.push({ op, args, expectLen, resolve }));
  }
  function pump() {
    if (pending || !queue.length) return;
    pending = queue.shift(); sim.requests++;
    let x = pending.op; for (const a of pending.args) x ^= a;
    send([0x4d, 0x53, pending.op, ...pending.args, x]);
  }
  setInterval(pump, 5);
  // background seeder traffic like a busy node (answering QUERYs, re-reading the catalogue)
  // Bursts of 4 reads with ~25 ms between them (USB latency + mesh loop); any console byte that lands
  // inside a burst is drained by the firmware's txn(), so the busy window covers the whole burst.
  let busyUntil = 0;
  setInterval(async () => {
    if (!sim.ready || pending || queue.length) return;
    sim.background = (sim.background || 0) + 1;
    busyUntil = performance.now() + 4 * 25 + 30;
    for (let i = 0; i < 4; i++) { await request(1, [], 1); await new Promise((r) => setTimeout(r, 25)); }
  }, 1200);
  function onBytes(bytes) {
    for (const b of bytes) {
      if (pending) {
        buf.push(b);
        if (buf.length >= 2 && (buf[0] !== 0x6d || buf[1] !== 0x73)) {
          // the firmware (MotaSourceSerial::txn) drains/skips these bytes: a console line sent now is lost
          sim.problems.push('console bytes arrived during a seeder request (firmware would drop them): ' + String.fromCharCode(...buf.slice(0, 2)));
          buf = []; continue; }
        const need = 5 + (buf[3] === 0 ? pending.expectLen : 0);
        if (buf.length >= 4 && buf.length === need) {
          let x = 0; for (let i = 0; i < need - 1; i++) x ^= buf[i];
          if (x !== buf[need - 1] || buf[2] !== pending.op) sim.problems.push('bad reply frame op ' + pending.op);
          const p = pending; pending = null; const payload = buf.slice(4, need - 1); buf = [];
          sim.replies.push({ op: p.op, status: p.status, len: payload.length });
          p.resolve({ status: buf[3], payload: Uint8Array.from(payload) });
        }
        continue;
      }
      if (performance.now() < busyUntil) {
        sim.problems.push('console byte arrived during a seeder burst (firmware would drop it): ' + String.fromCharCode(b));
        continue;
      }
      text += String.fromCharCode(b);
      if (b === 10) { const line = text.trim(); text = ''; if (line) onLine(line); }
    }
  }
  const u32 = (v) => [v & 255, (v >> 8) & 255, (v >> 16) & 255, (v >>> 24) & 255];
  async function serveSession() {
    const c = await request(1, [], 1);
    sim.count = c.payload[0];
    const d = (await request(2, [0], 38)).payload;
    const rd = (o) => d[o] | (d[o + 1] << 8) | (d[o + 2] << 16) | (d[o + 3] << 24);
    sim.desc = { mid: Array.from(d.slice(0, 4)), total: rd(14), leavesOff: rd(18), blocks: rd(22), payloadOff: rd(26), payloadSize: rd(30) };
    const chunks = [];
    const get = async (off, len) => { const r = await request(3, [0, ...u32(off), len & 255, len >> 8], len); chunks.push({ off, data: Array.from(r.payload) }); };
    await get(0, 8 + 233);                                        // header + manifest
    await get(sim.desc.leavesOff, Math.min(160, sim.desc.blocks * 8));
    sim.readsBeforeFetch = chunks.length;
    sim.chunks = chunks;
    sim.ready = true;
  }
  async function fetchBlocks(n) {
    for (let b = 0; b < n; b++) {
      const off = sim.desc.payloadOff + b * 1024, len = Math.min(171, sim.desc.payloadSize - b * 1024);
      const r = await request(3, [0, ...u32(off), len & 255, len >> 8], len);
      sim.chunks.push({ off, data: Array.from(r.payload) });
    }
    sim.fetched = true;
  }
  // `ota host <mid>`: the node copies the whole .mota from the page (sequential READs), then serves it itself
  async function hostCopy() {
    const chunks = []; sim.hostState = 'importing';
    for (let off = 0; off < sim.desc.total; off += 512) {
      const len = Math.min(512, sim.desc.total - off);
      const r = await request(3, [0, ...u32(off), len & 255, len >> 8], len);
      chunks.push(...r.payload); sim.hostCopied = off + len;
    }
    sim.hostCopy = chunks; sim.hostState = 'serving';
  }
  function onLine(line) {
    sim.lines.push(line);
    const mid = () => sim.desc.mid.map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    let h;
    if ((h = /^ota host ([0-9A-F]{8})$/.exec(line))) {
      sim.hostCmd = h[1];
      sendText(`  -> OK importing mid=${h[1]} (${sim.desc.total} B) from the folder; \`ota host\` shows progress\r\n`);
      setTimeout(hostCopy, 20); return;
    }
    if (line === 'ota host') {
      sim.hostPolls = (sim.hostPolls || 0) + 1;
      sendText(sim.hostState === 'serving' ? `  -> host: serving mid=${mid()} (${sim.desc.blocks} blocks)\r\n`
        : `  -> host: importing mid=${mid()} ${sim.hostCopied || 0}/${sim.desc.total} B from the folder — keep it connected\r\n`);
      return;
    }
    if ((h = /^ota host nudge ([0-9A-F]{12})( fetch)?$/.exec(line))) {
      (sim.hostNudges = sim.hostNudges || []).push(h[1]);
      sendText(`  -> OK this node nudges ${h[1]} (${h[2] ? 'fetch' : 'fetch+install'}) up to 5 times, 120s apart, once it is hosting\r\n`);
      return;
    }
    if (line === 'ota folder on') { sendText('  -> OK folder attached\r\n'); serveSession(); }
    const m = /^ota nudge ([0-9A-F]{12}) ([0-9A-F]{8})( fetch)?$/.exec(line);
    if (m) {
      sim.nudges.push(line);
      // the first nudge gets "lost" (no echo) to exercise the confirmation retry; later ones are confirmed
      if (sim.nudges.length > 1) sendText(`  -> OK nudged ${m[1]} -> mid=${m[2]} (${m[3] ? 'fetch' : 'fetch+install'}). It acts only if ...\r\n`);
      if (sim.nudges.length === 3) setTimeout(() => fetchBlocks(3), 200);   // the target starts fetching
    }
  }
  const writable = new WritableStream({ write(chunk) { sim.rx.push(...chunk); onBytes(chunk); } });
  const port = { readable, writable, open: async () => {}, close: async () => {}, getInfo: () => ({}) };
  Object.defineProperty(navigator, 'serial', { value: { requestPort: async () => port, addEventListener() {} } });
};

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ acceptDownloads: true });
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  await page.addInitScript(FAKE_SERIAL);
  await page.goto(PAGE);
  assert.strictEqual(await page.locator('#env').isHidden(), true, 'environment warning shown: ' + await page.locator('#env').textContent());

  await page.setInputFiles('#fw', path.join(D, 'esp_new.bin'));
  await page.setInputFiles('#base', path.join(D, 'esp_old.bin'));
  await page.fill('#key', fs.readFileSync(path.join(D, 'key.hex'), 'utf8').trim());
  await page.waitForSelector('#pub:not([hidden])');
  // automatic compression first: an LZMA-wrapped (codec 3) package, labelled and warned about
  await page.click('#build');
  await page.waitForSelector('#summary:not([hidden])', { timeout: 120000 });
  assert(/sequential \+ LZMA/.test(await page.textContent('#summary')), 'LZMA label');
  assert(/LZMA support/.test(await page.textContent('#buildmsg')), 'LZMA warning');
  const [dlz] = await Promise.all([page.waitForEvent('download'), page.click('#dl')]);
  fs.copyFileSync(await dlz.path(), path.join(D, 'page_lzma.mota'));
  console.log('ok    automatic compression built', dlz.suggestedFilename());
  await page.selectOption('#compress', 'crle');           // then plain CRLE: byte-identical to motatool
  const t0 = Date.now();
  await page.click('#build');
  await page.waitForSelector('#summary:not([hidden])', { timeout: 120000 });
  console.log('build in browser:', Date.now() - t0, 'ms;', (await page.textContent('#buildmsg')).trim());
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#dl')]);
  const got = fs.readFileSync(await dl.path()), want = fs.readFileSync(path.join(D, 'mt_seq.mota'));
  assert(got.equals(want), 'downloaded .mota differs from motatool');
  console.log('ok    downloaded package is byte-identical to motatool:', dl.suggestedFilename());

  await page.click('#connect');
  await page.waitForSelector('#serve:not([disabled])');
  await page.click('#serve');
  await page.waitForFunction(() => window.__sim.ready, null, { timeout: 10000 });
  const sim1 = await page.evaluate(() => window.__sim);
  assert.strictEqual(sim1.count, 1);
  assert.deepStrictEqual(sim1.desc.mid, Array.from(want.subarray(28, 32)), 'mid');
  assert.strictEqual(sim1.desc.total, want.length);
  for (const c of sim1.chunks) assert(Buffer.from(c.data).equals(want.subarray(c.off, c.off + c.data.length)), 'READ at ' + c.off);
  console.log('ok    COUNT/DESCRIBE/READ replies match the file');

  await page.fill('#targets', '693FAE0783D124C39624A5C8513F7EDD172BF7660AC5E3F9087D2C3D6DCAEB6E\nAABBCCDDEEFF');
  await page.click('details summary');
  await page.fill('#retry', '10');
  await page.click('#nudge');
  await page.waitForFunction(() => window.__sim.fetched, null, { timeout: 30000 });
  await page.waitForFunction(() => document.querySelector('#stopnudge').disabled, null, { timeout: 5000 });
  const sim = await page.evaluate(() => window.__sim);
  const mid = want.subarray(28, 32).toString('hex').toUpperCase();
  assert(sim.nudges.every((l) => l.endsWith(mid)), sim.nudges.join(' | '));
  assert(sim.nudges.some((l) => l.includes('693FAE0783D1')) && sim.nudges.some((l) => l.includes('AABBCCDDEEFF')));
  assert.strictEqual(sim.nudges.filter((l) => l.includes('693FAE0783D1')).length, 2, 'lost first nudge was re-sent once');
  assert.deepStrictEqual(sim.problems, [], 'wire problems: ' + sim.problems.join('; '));
  assert(sim.background >= 3, 'background traffic ran');
  for (const c of sim.chunks) assert(Buffer.from(c.data).equals(want.subarray(c.off, c.off + c.data.length)));
  const log = await page.textContent('#log');
  assert(/fetching blocks of this update/.test(log), 'fetch detection logged');
  const prog = await page.textContent('#progtext');
  console.log('ok    nudges:', sim.nudges.length, '| background seeder requests:', sim.background, '| progress:', prog.split('.')[0]);

  // hand the package over to the USB node: it copies the whole .mota, then takes over the nudges
  await page.click('#handover');
  await page.waitForFunction(() => /disconnect this computer now/.test(document.querySelector('#hostmsg').textContent), null, { timeout: 60000 });
  const sim2 = await page.evaluate(() => window.__sim);
  assert.strictEqual(sim2.hostCmd, mid, 'ota host <mid>');
  assert(Buffer.from(sim2.hostCopy).equals(want), 'the node copied the exact package');
  assert.deepStrictEqual(sim2.hostNudges.slice().sort(), ['693FAE0783D1', 'AABBCCDDEEFF'], 'host nudges: ' + sim2.hostNudges);
  assert.deepStrictEqual(sim2.problems, [], 'wire problems during hand-over: ' + sim2.problems.join('; '));
  assert(/2 of 2 node/.test(await page.textContent('#hostmsg')));
  console.log('ok    handed over: node copied', sim2.hostCopy.length, 'B, polls', sim2.hostPolls, '| node nudges', sim2.hostNudges.length);

  await page.click('#disconnect');
  await page.waitForFunction(() => /ota folder off\r\n$/.test(new TextDecoder().decode(Uint8Array.from(window.__sim.rx.slice(-40)))), null, { timeout: 8000 });
  const last = (await page.evaluate(() => new TextDecoder().decode(Uint8Array.from(window.__sim.rx.slice(-40)))));
  assert(/ota folder off\r\n$/.test(last), 'folder off sent on disconnect');
  console.log('ok    `ota folder off` sent on disconnect');
  await page.setViewportSize({ width: 390, height: 900 });
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  assert(!overflow, 'horizontal scroll at phone width');
  await page.screenshot({ path: path.join(D, 'page.png'), fullPage: true });
  assert.deepStrictEqual(errors, [], 'page errors: ' + errors.join('; '));
  console.log('\nall passed');
  await browser.close();
})().catch((e) => { console.error('FAIL', e.message); process.exit(1); });
