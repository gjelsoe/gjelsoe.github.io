/* page.js — UI + Web Serial for mota_push.html. Logic lives in mota_core.js. */
(function () {
  'use strict';
  const C = window.MotaCore.init({
    bsdiff: window.MeshCoreDetoolsBsdiff, pack: window.MeshCoreDetoolsPack, crle: window.MeshCoreDetoolsCrle,
    ed: window.nobleEd25519, subtle: window.crypto && window.crypto.subtle, lzma: window.MeshCoreLzmaEncoder,
  });
  const $ = (id) => document.getElementById(id);
  const S = C.SEEDER;

  // ---- environment ----
  const envProblems = [];
  if (!window.isSecureContext || !window.crypto || !window.crypto.subtle)
    envProblems.push('This page needs a secure context: open the file directly from disk (file://) or over https.');
  if (!('serial' in navigator))
    envProblems.push('This browser has no Web Serial. Use desktop Chrome or Edge. (You can still build and download a package.)');
  if (envProblems.length) { $('env').textContent = envProblems.join(' '); $('env').hidden = false; }

  // ---- log ----
  const logEl = $('log');
  function log(text, cls) {
    const line = document.createElement('div');
    const t = new Date().toTimeString().slice(0, 8);
    line.textContent = `${t}  ${text}`;
    if (cls) line.className = cls;
    const stick = logEl.scrollTop + logEl.clientHeight >= logEl.scrollHeight - 4;
    logEl.appendChild(line);
    while (logEl.childNodes.length > 800) logEl.removeChild(logEl.firstChild);
    if (stick) logEl.scrollTop = logEl.scrollHeight;
  }
  function msg(el, text, kind) { el.textContent = text; el.className = 'msg ' + (kind || ''); el.hidden = !text; }

  // ---- delta worker (Blob URL so it also works from file://) ----
  let worker = null, jobs = new Map(), jobId = 0;
  try {
    worker = new Worker(URL.createObjectURL(new Blob([window.MOTA_WORKER_SRC], { type: 'text/javascript' })));
    worker.onmessage = (e) => { const j = jobs.get(e.data.id); if (!j) return; jobs.delete(e.data.id);
      e.data.error ? j.reject(new Error(e.data.error)) : j.resolve(e.data.patch); };
  } catch (e) { worker = null; }
  function wrap(patch) {
    if (!worker) return Promise.resolve(C.lzmaWrap(patch));
    return new Promise((resolve, reject) => { const id = ++jobId; jobs.set(id, { resolve, reject });
      worker.postMessage({ id, kind: 'lzma', from: patch.slice() }); });
  }
  function encode(kind, from, to) {
    if (!worker) return Promise.resolve(kind === 'in-place' ? C.encodeInPlace(from, to) : C.encodeSequential(from, to));
    return new Promise((resolve, reject) => { const id = ++jobId; jobs.set(id, { resolve, reject });
      worker.postMessage({ id, kind, from: from.slice(), to: to.slice() }); });
  }

  // ---- inputs ----
  async function readFirmware(file) {
    const buf = new Uint8Array(await file.arrayBuffer());
    if (/\.hex$/i.test(file.name)) return { image: C.parseIntelHex(new TextDecoder().decode(buf)), kind: 'hex' };
    if (/\.mota$/i.test(file.name)) return { mota: buf, kind: 'mota' };
    return { image: buf, kind: 'bin' };
  }
  let seed = null;
  async function updateKey() {
    seed = null; $('pub').hidden = true;
    const v = $('key').value.trim();
    if (!v) { $('signerhint').textContent = '<your signing public key>'; refresh(); return; }
    try {
      seed = C.parseSeed(v);
      const pub = C.toHex(await C.publicKey(seed));
      $('pub').innerHTML = ''; $('pub').append('Signer public key: ');
      const c = document.createElement('code'); c.textContent = pub; $('pub').append(c);
      $('signerhint').textContent = pub;
    } catch (e) { $('pub').textContent = 'Signing key: ' + e.message; }
    $('pub').hidden = false; refresh();
  }
  $('key').addEventListener('input', updateKey);
  $('keyload').addEventListener('click', (e) => { e.preventDefault(); $('keyfile').click(); });
  $('keyfile').addEventListener('change', async () => {
    const f = $('keyfile').files[0]; if (!f) return;
    $('key').value = new TextDecoder().decode(new Uint8Array(await f.arrayBuffer())).trim(); $('keyfile').value = ''; updateKey();
  });
  $('keygen').addEventListener('click', async (e) => {
    e.preventDefault();
    const s = crypto.getRandomValues(new Uint8Array(32)), pub = C.toHex(await C.publicKey(s));
    download(new Blob([C.toHex(s).toLowerCase() + '\n']), 'mota_signing.key');
    download(new Blob([pub.toLowerCase() + '\n']), 'mota_signing.key.pub');
    $('key').value = C.toHex(s).toLowerCase(); updateKey();
    log('Created a new signing key (saved as mota_signing.key / .pub). Keep the .key file private.', 'ok');
  });

  // ---- build ----
  let pkg = null;   // { bytes, m, name }
  function refresh() {
    const conn = !!port;
    $('build').disabled = !$('fw').files[0] || building;
    $('dl').disabled = !pkg;
    $('serve').disabled = !(conn && pkg) || serving;
    $('nudge').disabled = !(conn && pkg && serving && pkg.m.signed) || !!nudger || !!handover;
    $('handover').disabled = !(conn && pkg && serving && pkg.m.signed) || !!nudger || !!handover;
    $('stopnudge').disabled = !nudger;
    $('disconnect').disabled = !conn; $('connect').disabled = conn || !('serial' in navigator);
    $('cmd').disabled = $('send').disabled = !conn;
  }
  ['fw', 'base', 'ptype', 'compress'].forEach((id) => $(id).addEventListener('change', () => { pkg = null; $('summary').hidden = true; msg($('buildmsg'), ''); refresh(); }));
  let building = false;
  $('build').addEventListener('click', async () => {
    building = true; refresh(); const t0 = performance.now();
    try {
      const fw = await readFirmware($('fw').files[0]);
      let bytes;
      if (fw.mota) {
        bytes = fw.mota;
        const p = await C.verifyMota(bytes);
        if (p.length) throw new Error('.mota does not verify: ' + p.join('; '));
      } else {
        let base = null;
        if ($('base').files[0]) {
          const b = await readFirmware($('base').files[0]);
          if (!b.image) throw new Error('installed firmware must be a .bin or .hex');
          base = b.image;
        }
        let ptype = $('ptype').value;
        if (ptype === 'auto') ptype = fw.kind === 'hex' ? 'in-place' : 'sequential';
        msg($('buildmsg'), base ? `Computing ${ptype} delta… (an nRF52 in-place delta can take a minute)` : 'Building…');
        ({ bytes } = await C.buildMota({ image: fw.image, base, patchType: ptype, seed, encode, wrap,
          compress: $('compress').value }));
        const p = await C.verifyMota(bytes);
        if (p.length) throw new Error('self-check failed: ' + p.join('; '));
      }
      const m = C.parseMota(bytes);
      pkg = { bytes, m, name: C.suggestedName(m) };
      showSummary(m, bytes.length, (performance.now() - t0) / 1000);
    } catch (e) { pkg = null; $('summary').hidden = true; msg($('buildmsg'), e.message, 'err'); }
    building = false; refresh();
  });
  function showSummary(m, size, secs) {
    const kind = m.codec === C.CODEC.FULL ? 'Full image' : m.codec === C.CODEC.SEQUENTIAL ? 'Delta, sequential (ESP32)'
      : m.codec === C.CODEC.SEQUENTIAL_LZMA ? 'Delta, sequential + LZMA (ESP32)' : 'Delta, in-place (nRF52)';
    const rows = [
      ['Update', `${kind}, v${C.versionStr(m.fwVersion)} for ${m.hwId || '?'}`],
      ['Target id', '0x' + m.targetId.toString(16).toUpperCase().padStart(8, '0')],
      ['Size', `${size.toLocaleString()} B (${m.blockCount} blocks, ≈${C.dataPackets(m.payloadSize).toLocaleString()} data packets)`],
      ['Update id (mid)', C.toHex(m.mid)],
      ...(m.full ? [] : [['Only for node running', `this fw ${C.toHex(m.baseHash.subarray(0, 4))}  (check with \`ota\` on the node)`]]),
      ['Signed by', m.signed ? C.toHex(m.signer) : 'not signed'],
      ['File', pkg.name],
    ];
    const dl = $('summary'); dl.innerHTML = '';
    for (const [k, v] of rows) { const dt = document.createElement('dt'), dd = document.createElement('dd'); dt.textContent = k; dd.textContent = v; dl.append(dt, dd); }
    dl.hidden = false;
    const warn = [];
    if (!m.full) warn.push(`This delta installs only on a node whose \`ota\` shows "this fw ${C.toHex(m.baseHash.subarray(0, 4))}". A node running other firmware cannot install it.`);
    if (!m.signed) warn.push('Not signed: a node only acts on an update request for a package signed by a key it trusts. Add your signing key and build again.');
    if (m.codec === C.CODEC.SEQUENTIAL_LZMA) warn.push('LZMA-compressed: only nodes running firmware with LZMA support fetch it (older OTA firmware ignores it). For older nodes choose Compression: Off.');
    if (m.codec === C.CODEC.INPLACE && size > C.NRF52_MAX_INPLACE_MOTA) warn.push(`Larger than the nRF52 staging area (${C.NRF52_MAX_INPLACE_MOTA.toLocaleString()} B): the node cannot store it.`);
    if (m.codec === C.CODEC.FULL && m.hwId && /RAK|nRF|T114|T096|T1000|XIAO/i.test(m.hwId)) warn.push('A full nRF52 image is large; a delta against the installed firmware is usually far smaller.');
    msg($('buildmsg'), warn.length ? warn.join(' ') : `Built and self-checked in ${secs.toFixed(1)} s.`, warn.length ? 'warn' : 'ok');
    $('signerhint').textContent = m.signed ? C.toHex(m.signer) : '<your signing public key>';
  }
  function download(blob, name) {
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }
  $('dl').addEventListener('click', () => pkg && download(new Blob([pkg.bytes]), pkg.name));

  // ---- serial link ----
  let port = null, reader = null, writer = null, writeChain = Promise.resolve(), parser = null;
  let core = null, serving = false, nudger = null, tick = null, served = null, handover = null, hoTick = null;
  function write(bytes) { const w = writer; writeChain = writeChain.then(() => w && w.write(bytes)).catch(() => {}); return writeChain; }
  // Replies larger than the node's serial RX buffer are written in slices with a short pause: on ESP32-S3
  // native USB (HWCDC, e.g. Heltec V4) the default RX buffer is 256 bytes and overflowing bytes are dropped,
  // so a 1 KB block reply arrived corrupted and the node silently skipped sending that block.
  const SLICE = 128, SLICE_GAP_MS = 4;
  function writePaced(bytes) {
    if (bytes.length <= SLICE) return write(bytes);
    const w = writer;
    writeChain = writeChain.then(async () => {
      for (let o = 0; o < bytes.length && w; o += SLICE) {
        await w.write(bytes.subarray(o, o + SLICE));
        if (o + SLICE < bytes.length) await new Promise((res) => setTimeout(res, SLICE_GAP_MS));
      }
    }).catch(() => {});
    return writeChain;
  }
  function writeLine(text) { log('> ' + text); return write(new TextEncoder().encode(text + '\r\n')); }

  // Console lines share the wire with the node's seeder requests. While the node waits for a seeder reply it
  // drains and skips every other byte on its serial input (MotaSourceSerial::txn), so a console line that
  // arrives then is lost or cut in half. Write console lines only after the seeder traffic has been quiet.
  const QUIET_MS = 800;
  let lastReqAt = 0, consoleQ = [], linkTick = null;
  const quiet = () => parser && !parser.inFrame && Date.now() - lastReqAt >= QUIET_MS;
  function queueLine(text) { consoleQ.push(text); pumpConsole(); }
  function pumpConsole() { if (writer && consoleQ.length && quiet()) writeLine(consoleQ.shift()); }
  let stats = null, lastManifestNote = 0;
  function resetStats() { stats = { manifest: 0, leaves: 0, blocks: 0 }; }

  $('connect').addEventListener('click', async () => {
    try {
      port = await navigator.serial.requestPort();
      await port.open({ baudRate: +$('baud').value, bufferSize: 8192 });
      writer = port.writable.getWriter(); parser = new C.WireParser();
      $('dot').classList.add('on'); $('conn').textContent = 'Connected';
      log('Connected to the USB node.', 'ok'); consoleQ = []; linkTick = setInterval(pumpConsole, 100); refresh(); readLoop();
    } catch (e) { port = null; if (e.name !== 'NotFoundError') log('Connect failed: ' + e.message, 'err'); refresh(); }
  });
  async function readLoop() {
    while (port && port.readable) {
      reader = port.readable.getReader();
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          for (const ev of parser.feed(value)) onWire(ev);
        }
      } catch (e) { if (port) log('Serial read error: ' + e.message, 'err'); }
      finally { try { reader.releaseLock(); } catch (e) {} }
      if (!port) break;
    }
  }
  function onWire(ev) {
    if (ev.type === 'line') {
      log(ev.text, 'dev');
      if (nudger) nudger.onLine(ev.text, Date.now());
      if (handover) {                                         // an error is logged once, when the hand-over ends
        const note = handover.onLine(ev.text, Date.now());
        if (note && note.level !== 'err') log(note.text, note.level === 'info' ? '' : note.level);
        handoverTick();
      }
      return;
    }
    if (ev.type !== 'req') return;
    lastReqAt = Date.now();
    if ($('verbose').checked) log(`seeder ${['', 'COUNT', 'DESCRIBE', 'READ'][ev.op] || 'op ' + ev.op} ${C.toHex(ev.args)}`, 'dev');
    if (nudger) { const note = nudger.onRequest(ev.op, ev.args); if (note) log(note, 'ok'); }
    if (!core) return;                                        // not serving: let the node time out
    const r = core.handle(ev.op, ev.args);
    if (!r) return;
    writePaced(C.encodeResponse(ev.op, r[0], r[1]));
    if (ev.op === S.OP_READ && r[0] === S.OK) trackRead(ev.args);
  }
  function trackRead(args) {
    const off = args[1] | (args[2] << 8) | (args[3] << 16) | (args[4] << 24), len = args[5] | (args[6] << 8), m = pkg.m;
    if (handover && (handover.state === 'sent' || handover.state === 'importing')) {   // the USB node copying it
      handover.onRead(off, len, Date.now());
      $('progress').style.width = handover.pct + '%';
      $('progtext').textContent = `Copying the update to the USB node: ${handover.pct}%.`;
      return;
    }
    if (off + len <= m.payloadOff) {
      if (off < m.leavesOff) {
        stats.manifest++;
        if (nudger && Date.now() - lastManifestNote > 15000) {
          lastManifestNote = Date.now();
          log('A node is reading this update\'s manifest (it checks the signature before fetching blocks).', 'ok');
        }
      } else stats.leaves++;
      showStats(); return;
    }
    stats.blocks++;
    for (let b = Math.floor(Math.max(0, off - m.payloadOff) / 1024); b * 1024 < off + len - m.payloadOff && b < m.blockCount; b++) served.add(b);
    const pct = Math.round(100 * served.size / m.blockCount);
    $('progress').style.width = pct + '%';
    $('progtext').textContent = `${served.size} of ${m.blockCount} blocks read by the mesh (${pct}%). A block is read again for each node that asks for it.`;
    showStats();
  }
  function showStats() {
    $('stats').textContent = `Reads by the USB node: manifest ${stats.manifest}, leaves ${stats.leaves}, blocks ${stats.blocks}.`;
  }

  $('serve').addEventListener('click', async () => {
    core = new C.SeederCore([pkg.bytes]); served = new Set(); serving = true; resetStats(); showStats();
    $('progress').style.width = '0%'; $('progtext').textContent = 'Serving; waiting for the mesh to ask for blocks.';
    queueLine('ota folder on');
    log(`Serving ${pkg.name} (mid ${C.toHex(pkg.m.mid)}).`, 'ok'); refresh();
  });

  $('nudge').addEventListener('click', () => {
    let prefixes;
    try { prefixes = C.parseTargets($('targets').value); } catch (e) { log(e.message, 'err'); return; }
    if (!prefixes.length) { log('Enter at least one node public key.', 'err'); return; }
    nudger = new C.Nudger({ prefixes, mid: pkg.m.mid, install: $('install').checked, payloadOff: pkg.m.payloadOff,
      retryMs: Math.max(10, +$('retry').value || 120) * 1000, maxTries: Math.max(1, +$('tries').value || 5), now: Date.now() });
    nudger.catalogSeen = true;                                // the node already has the catalogue (we are serving)
    log(`Requesting the update on ${prefixes.length} node(s).`);
    tick = setInterval(nudgeTick, 500); renderTargets(); refresh();
  });
  function nudgeTick() {
    if (!nudger || !writer) return;
    if (!consoleQ.length && quiet()) { const line = nudger.poll(Date.now()); if (line) writeLine(line); }
    renderTargets();
    if (nudger.finished) {
      log(nudger.fetching ? 'The mesh is fetching the update. Keep this page open until the nodes have it.'
        : 'Stopped sending requests: no node started fetching. Check the setup on the node (ota key / ota config push).', nudger.fetching ? 'ok' : 'err');
      stopNudging();
    }
  }
  function stopNudging() { clearInterval(tick); tick = null; renderTargets(); nudger = null; refresh(); }
  $('stopnudge').addEventListener('click', () => { log('Stopped sending requests.'); stopNudging(); });

  // ---- hand the package over to the USB node (`ota host`): it keeps it, serves it and nudges by itself ----
  $('handover').addEventListener('click', () => {
    let prefixes;
    try { prefixes = C.parseTargets($('targets').value); } catch (e) { log(e.message, 'err'); return; }
    handover = new C.Handover({ mid: pkg.m.mid, total: pkg.bytes.length, prefixes, install: $('install').checked, now: Date.now() });
    log(`Handing the update over to the USB node${prefixes.length ? ` (it will request it on ${prefixes.length} node(s))` : ''}.`);
    msg($('hostmsg'), 'Copying the update to the USB node. Keep the page open until this says you can disconnect.', '');
    hoTick = setInterval(handoverTick, 300); refresh();
  });
  function handoverTick() {
    if (!handover || !writer) return;
    if (!consoleQ.length && quiet()) { const line = handover.poll(Date.now()); if (line) writeLine(line); }
    if (handover.state === 'hosting' || handover.state === 'done') {
      $('progress').style.width = '100%';
      $('progtext').textContent = 'The USB node holds the update and serves it to the mesh.';
    }
    if (!handover.finished) return;
    clearInterval(hoTick); hoTick = null;
    if (handover.state === 'done') {
      const n = handover.t.length, ok = handover.t.filter((t) => t.confirmed).length;
      const text = 'Done: the USB node keeps the update and serves it' + (n ? ` and requests it on ${ok} of ${n} node(s) itself` : '')
        + '. You can disconnect this computer now. Check with `ota host` on the node.';
      log(text, 'ok'); msg($('hostmsg'), text, 'ok');
    } else {
      log(handover.error, 'err'); msg($('hostmsg'), handover.error, 'err');
    }
    handover = null; refresh();
  }
  function renderTargets() {
    if (!nudger) return;
    const tb = $('ttable').querySelector('tbody'); tb.innerHTML = '';
    for (const t of nudger.t) {
      const tr = document.createElement('tr');
      const state = nudger.fetching ? 'Fetching' : nudger.done(t) ? 'No response' : t.pendingAt !== null ? 'Waiting for repeater' : t.sent ? 'Waiting to re-send' : 'Queued';
      [t.prefix, t.sent, t.confirmed, state].forEach((v, i) => { const td = document.createElement('td'); td.textContent = v; if (!i) td.className = 'mono'; tr.append(td); });
      tb.append(tr);
    }
    $('ttable').hidden = false;
  }

  async function disconnect() {
    const p = port;
    if (nudger) stopNudging();
    if (handover) {                                         // disconnected mid-copy: the node gives up by itself
      clearInterval(hoTick); hoTick = null;
      if (handover.state !== 'hosting') msg($('hostmsg'), 'Disconnected before the USB node had the whole update; it was not handed over.', 'warn');
      handover = null;
    }
    clearInterval(linkTick); linkTick = null; consoleQ = [];
    if (serving && writer) {
      for (let i = 0; i < 30 && !quiet(); i++) await new Promise((r) => setTimeout(r, 100));   // up to 3 s for a gap
      await writeLine('ota folder off'); await new Promise((r) => setTimeout(r, 300));
    }
    serving = false; core = null; port = null;
    try { if (reader) await reader.cancel(); } catch (e) {}
    try { if (writer) { await writeChain; writer.releaseLock(); } } catch (e) {}
    writer = null;
    try { if (p) await p.close(); } catch (e) {}
    $('dot').classList.remove('on'); $('conn').textContent = 'Not connected'; log('Disconnected.'); refresh();
  }
  $('disconnect').addEventListener('click', disconnect);
  if ('serial' in navigator) navigator.serial.addEventListener('disconnect', (e) => { if (port && e.target === port) { log('USB node unplugged.', 'err'); disconnect(); } });
  window.addEventListener('beforeunload', (e) => { if (serving) { e.preventDefault(); e.returnValue = ''; } });

  function sendCmd() { const v = $('cmd').value.trim(); if (!v || !writer) return; queueLine(v); $('cmd').value = ''; }
  $('send').addEventListener('click', sendCmd);
  $('cmd').addEventListener('keydown', (e) => { if (e.key === 'Enter') sendCmd(); });
  refresh();
})();
