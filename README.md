# MeshCore OTA Push (browser)

`mota_push.html` is a single, self-contained page: open it from disk in desktop **Chrome or Edge** (Web
Serial). No server, no network, no account — the firmware files and your signing key never leave the computer.

It does what `motatool build` + `motatool serve --nudge` do ("method A", docs/ota_protocol.md §8.7):

1. **Package** — pick the new firmware (ESP32 `firmware.bin`, nRF52 `firmware.hex`, or a ready `.mota`) and,
   optionally, the firmware currently installed on the node to get a small delta (`.hex` → nRF52 in-place,
   `.bin` → ESP32 sequential). The page builds a format-v3 `.mota` and signs it with your Ed25519 key
   (`motatool keygen` format: 64 hex chars; the page can also create one). Output is byte-identical to motatool.
2. **Repeater on USB** — connect any node running OTA firmware; *Start serving* sends `ota folder on` and the
   page answers its `mota-seeder` requests, so the node relays the package to the mesh.
3. **Nodes to update** — paste public keys (full or ≥ 12 hex chars). The page sends `ota nudge <key> <mid>` on the
   node's console, re-sends until the node confirms (`OK nudged`) and until the mesh starts fetching blocks.

Each target acts only if it was set up once with `ota key add <your signer public key>` and
`ota config push trusted` — it checks the signature before it downloads anything, so no password is involved.
Keep the page open until the nodes have the update; *Disconnect* sends `ota folder off`.

Or click **Hand over to the USB node**: the page sends `ota host <mid>`, the node copies the package into its
own flash (the page shows the copy from the READs it answers), verifies it and serves it itself; the page then
sends `ota host nudge <key>` for each target, and the computer can be disconnected (docs/ota_protocol.md §8.8).
The USB node needs firmware with `ota host` and must trust the signing key too.

## Build and test

```sh
python3 tools/mota/web/build.py                   # src/ + vendor/ -> mota_push.html (+ dist/ for tests)
node tools/mota/web/test/core.test.js <fixtures>  # .mota bytes vs motatool, seeder, wire parser, nudger
node tools/mota/web/test/page.test.js <fixtures>  # Playwright: whole page against a simulated node
```

Fixtures: `esp_old.bin esp_new.bin nrf_old.bin nrf_new.bin` (EndF-trailed OTA builds), `key.hex`, and the
motatool references `mt_full.mota` (`--fw esp_new.bin --sign key.hex`), `mt_seq.mota` (`+ --base esp_old.bin`),
`mt_ip.mota` (`--fw nrf_new.bin --base nrf_old.bin --patch-type in-place --sign key.hex`).

## Third-party code (vendor/)

- `detools-js/` — bsdiff / CRLE / pack-size from detools-js 0.1.0 (MIT, Ahmet Ucar; bsdiff BSD-2 Colin Percival),
  in the browser adaptation from github.com/mikecarper/MeshCore. See `vendor/detools-js/LICENSE`, `NOTICE.md`.
- `lzma-js/` — LZMA-JS 2.3.2 compress build (MIT, Nathan Rugg; port of Igor Pavlov's public-domain LZMA SDK),
  with small marked changes for a 4 KB dictionary and lc/lp/pb 0 — see `vendor/lzma-js/NOTICE.md`.
- `noble-ed25519/` — @noble/ed25519 2.3.0 (MIT, Paul Miller), npm tarball SHA-256
  `92ef39271cdf5879b04654907d02697d034f92a52ec9aebc1b36d3cdb634154b`.
