# Updating your node over the air (OTA) — user guide

This guide is for **node operators**: how to update your MeshCore device's firmware over the radio, in
plain language. No cables, no programmer — your node can download a new firmware from a neighbour and
install it. (For the technical wire format, see [the OTA protocol spec](ota_protocol.md).)

> **Is my node supported?** OTA works on **ESP32** boards (e.g. Heltec V3) and on the **RAK4631** (nRF52,
> which needs the special MeshCore bootloader). Other boards build fine but can't self-update yet.

---

## The important part first: it's safe

- **Nothing installs by itself.** Your node can *discover* and *download* an update in the background, but
  it only **installs** when you say so (unless you deliberately turn on auto-install — see below).
- **Bad downloads can't sneak in.** Every piece of the firmware is checked against a cryptographic
  fingerprint as it arrives, and the whole image is verified again before install. A corrupt or tampered
  download is rejected, not installed.
- **You choose who to trust.** Updates can be *signed* by their author. You can tell your node to only
  auto-install firmware signed by keys you've added.
- **It won't disrupt your mesh.** OTA traffic is always the **lowest priority** — your node only spends
  spare airtime on it. Messages and routing always come first; a busy node simply updates later. Think of
  it as *"eventually upgradable."*
- **It can recover.** If an install ever fails, the node falls back to a safe recovery mode (you can
  re-flash a known-good firmware over USB) — it won't be left bricked.

---

## How to talk to your node

Connect to your node's **console** — usually a USB serial terminal at **115200 baud** (or whatever tool
you already use to manage the node). You type `ota ...` commands and the node replies in plain words.

The commands have short, friendly names (and most accept aliases, so you don't have to remember exact
spelling): type **`ota help`** any time to see the list, or just **`ota`** for a status summary.

---

## Common tasks

### 1. See what I'm running and whether anything is going on

```
ota status
```

Shows your current firmware version, your node's update "target" (its hardware/role id), and whether a
download is in progress.

For a denser admin view — your firmware's content id (`mid`) **and** its body hash, the fingerprint of the
set you're serving, live download progress, and the current policy — use:

```
ota stats
```

On a remote node this is **admin-only** (the remote command console requires the admin password) — send it
from the app's repeater command screen, or the WiFi/serial OTA console.

### 2. Find updates available near me

```
ota ls
```

Your node asks around and lists the firmware updates other nodes nearby are offering, in plain words —
each with a **number**, its version, whether it's a full image or a small delta, how many nodes have it,
and how recently it was seen. For example:

```
Updates nearby (2 src) — `ota get <#>` to download:
 1) v1.2.3 delta [yours] 3n 5s
 2) v1.2.0 full [other hw] 1n 12s [downloading]
```

Each row shows the version, full-vs-delta, **whether it fits your node**, how many nodes have it, and how
long ago it was seen. The fit marker:

- **[yours]** — built for your exact hardware **and** role; safe to install.
- **[other hw]** — a different board or role (e.g. a companion image, or another board). Don't install it.
- **[?]** — can't tell (a build with no target id set, e.g. a bare IDE build rather than a release build).

Run it again after a few seconds — discovery happens in the background, so the list fills in. Nothing is
downloaded yet; this is just looking around. (`ota neighbors` / `ota updates` also work.)

### 3. Download an update

Pick one from the list by its **number**, and say **where** to put it:

```
ota pull 1 flash            # stage it in this node's flash, to install here
ota pull 1 folder           # capture it onto a connected motatool folder as <id>.mota (don't install here)
ota pull 1 folder validate  # same capture, warm-started from a motatool --seed build (much faster; below)
```

The destination is required — `ota pull 1` on its own just shows the choices. **`flash`** is always
available (stage here, then `ota install`). **`folder`** appears only while a `motatool serve` link is
attached (it shows the link, e.g. `folder: tcp 192.168.4.5`); it streams the firmware straight onto the
host folder — nothing is staged on this node. That's how you grab an **exact copy of another device's
firmware** off the mesh (to a `.mota` file) so you can later build a *delta* against firmware you don't
otherwise have. (`ota get` is an alias.)

**`validate` (warm-start, advanced).** Capturing a full image over the radio is slow. If you have a
*similar* build on the computer (e.g. a fresh recompile of the same firmware), run motatool with
`--seed <that.mota>` and add **`validate`**: the node fetches just the target's block fingerprints, keeps
every block your seed already matches, and pulls over the radio only the handful that actually differ —
turning a ~30-minute capture into seconds. The result is still a byte-exact, verified copy of the target.

*Where the seed comes from:* it is the **`--seed <file>` you pass to `motatool serve`** — **not** a file you
drop into the capture (`--dir`) folder, which is only the destination and starts empty. There is exactly one
configured seed. When you run `... folder validate`, the node asks motatool to begin the capture and motatool
stamps that seed's payload into the fresh `.part` in the same step — so it is always the file you named, with
no guessing. **`validate` is the switch:** a plain `folder` pull ignores any seed and fetches from scratch;
re-running a `validate` pull re-begins fresh (it never resumes a stale partial). Nothing about the seed is
trusted — every kept block is checked against the target's own fingerprints, so a mismatched or missing seed
just means those blocks are fetched over the radio (correct result, only slower).

The node fetches in the background, **at low priority**, a piece at a time — possibly from several
neighbours at once. Check progress with `ota status`. You can keep using your node normally meanwhile.

If a `folder` pull loses its link mid-transfer, `ota status` shows **paused** — the host keeps the
partial and the pull resumes (filling only what's missing) the moment you reconnect motatool; it never
falls back to flash. To **stop** a download you no longer want:

```
ota cancel
```

### 4. Install a downloaded update

Once `ota status` shows the download is **ready to install**:

```
ota install
```

The node verifies the firmware one last time, and if everything checks out it installs it and **reboots
into the new version**. If the check fails, it tells you why and does **not** install. (If you haven't
added the signer's key, an unsigned/untrusted image will only install with this explicit command — never
automatically.)

After it reboots, run `ota status` to confirm the new version.

### 5. If something goes wrong

- A download that stalls or gets interrupted just **resumes** later, or you can `ota cancel` and try again.
- If an **install** fails, the node won't boot a broken image — it lands in **recovery mode**:
  - **RAK4631 / nRF52:** if power is lost *during* an install, a power-safe bootloader (`ota status` shows
    `bl:apply+resume`) simply continues the install at the next power-up. If an install genuinely fails, the
    node waits in Bluetooth update mode (update it from the nRF DFU phone app) or, after a double-press of
    reset, appears as a USB drive; drag a known-good firmware `.uf2` onto it to recover.
  - **ESP32:** it keeps the previous firmware in the other slot and rolls back.
- When in doubt, you can always re-flash over USB the normal way.

---

## Optional: let it update automatically

By default your node only *discovers* updates — it won't download or install on its own. If you want more
automation (e.g. for a remote node you can't easily reach), you can opt in. These settings are saved.

```
ota config autofetch any        # auto-DOWNLOAD any compatible update for this node (still won't install)
ota config autofetch signed     # auto-download only signed updates
ota config autofetch off        # back to manual (default)

ota config autoinstall trusted  # auto-INSTALL a downloaded update IF it's signed by a key you trust
ota config autoinstall off      # never auto-install (default)

ota config advert 1440          # re-advertise this node every N minutes (default 1440 = 24h)
ota config advert 0             # disable periodic re-advertise (still advertises briefly at boot)

ota config hops 3               # how far OTA travels: accept from / relay up to N repeater hops (default 3)
ota config hops 0               # only exchange OTA with directly-connected nodes (never relay)

ota config push trusted         # let an operator push ONE update to this node by name (see below)
ota config push off             # ignore such requests (default)

ota config                      # show the current settings
```

Recommended for most people: leave both **off** and update by hand. Use `autoinstall trusted` only once
you've added the signer's key (next section) and you trust them to push updates unattended.

---

## Optional: only trust updates from specific people

If you'll use auto-install, tell your node which signing keys to trust. The firmware author shares their
**public** key (a hex string); you add it:

```
ota key add <public-key-hex>    # trust this signer
ota key list                    # show trusted signers
ota key rm <public-key-hex>     # stop trusting one
```

Only updates signed by a trusted key are eligible for auto-install. Manual `ota install` still lets you
install anything yourself, on your own responsibility.

---

## Let someone update this node remotely ("push")

If you look after a node you can't easily reach (a repeater on a mast), you can let it accept an update that
is aimed at it specifically. On the node, once:

```
ota key add <your signing public key>   # who may push updates
ota config push trusted
```

From your computer, with any of your nodes on USB:

```
motatool serve --dir ./rollout --serial /dev/ttyACM0 --nudge <the remote node's public key>
```

No command line? Open `tools/mota/web/mota_push.html` in Chrome or Edge: it builds the signed update (also a
small delta) in the browser and does the same through your USB node — see [its README](../tools/mota/web/README.md).

Only that node reacts, and only to an update signed by a key it trusts — it checks the signature before it
downloads anything, so nobody can push it an update you didn't sign, and no password is sent over the air.
It then downloads, verifies and installs it by itself. Or by hand on the USB node: `ota nudge <pubkey> <mid>`.
If the remote node restarts in the middle, just nudge it again; it carries on where it stopped.

Don't want to leave the computer running? On the page, click **Hand over to the USB node** instead (or
`ota host <mid>` on the USB node while the folder is attached). The USB node copies the update into its own
memory, checks it, serves it to the mesh and sends the update requests itself (`ota host nudge <pubkey>`),
so you can unplug the computer. The USB node must trust your signing key too (`ota key add`), and it keeps one
update at a time; if it gets an update for itself, that one wins. `ota host` shows what it is doing.

An ESP32 node that was updated with a small update keeps offering that update afterwards (`ota status` shows
`prev-delta:`), so neighbours that still run the old firmware can get it from this node.

To update *this* node to a specific update you can see in `ota ls`: `ota update <mid>` (add `fetch` to only
download it).

---

## Sharing updates with others (advanced)

### Relay a folder of firmware from a computer

If your node is connected to a computer (e.g. a gateway on a Raspberry Pi), it can **hand out** a whole
folder of firmware files to the mesh — without storing them itself. Useful for seeding a new release to a
remote area.

1. Put the firmware files (`.mota` files — see below) in a folder on the computer.
2. Install the helper tool once — the standalone `motatool` CLI (<https://github.com/vk496/motatool>) —
   then point it at your node and the folder — over the node's **USB serial**, or over **WiFi** if it's
   an ESP32 companion on your network:
   ```
   git clone https://github.com/vk496/motatool && cargo install --path ./motatool
   # over USB serial:
   motatool serve --dir ./my_firmware/ --serial /dev/ttyACM0 -v
   # …or over WiFi (ESP32 companion): the seeder is on a DEDICATED port (5001), separate from the
   # phone-app port (5000), so a phone can stay connected while you serve:
   motatool serve --dir ./my_firmware/ --tcp 192.168.1.50:5001 -v
   ```
   It answers the node's requests; your node then advertises those updates to neighbours, who can
   `ota get` them like any other. (A WiFi node prints its IP + seeder port to the serial log on connect.
   Details: <https://github.com/vk496/motatool>.)

To stop, just stop the daemon — over WiFi the node auto-detaches when the connection closes; over USB you
can also run `ota folder off` on the node. `ota folder` on its own lists what your node is offering.

### Everyone helps share

You don't have to be a gateway to help. Once **any** node finishes downloading an update, it automatically
offers it to *its* neighbours too. So a new firmware spreads outward node-to-node, instead of everyone
hammering the one node that had it first — and no node is ever overloaded, because all of this stays
lowest-priority.

---

## Where firmware files come from

OTA distributes **`.mota`** files — a packaged, verifiable firmware image (full image or a small "delta"
that only contains what changed). You get them by:

- **Downloading a build.** This fork publishes a rolling **`dev-latest`** release on GitHub with the
  current firmware for many boards, each accompanied by a `.full.mota` and a tiny `.delta.mota`. Grab the
  one for your board to test.
- **Building your own** with the `mota` packaging tool — see [tools/mota/README.md](../tools/mota/README.md)
  (this is for people distributing updates, not everyday operators).

---

## Quick reference

| I want to… | Command |
|---|---|
| List all commands | `ota help` |
| See my firmware + any download | `ota status` (or just `ota`) |
| Admin: ids/hashes + serving + policy | `ota stats` (admin-only remotely) |
| Find updates nearby | `ota ls` |
| Download update #1 | `ota get 1` |
| Cancel a download | `ota cancel` |
| Install a finished download | `ota install` |
| Turn on auto-download | `ota config autofetch any` |
| Turn on auto-install (trusted only) | `ota config autoinstall trusted` |
| Only offer small updates (deltas), never this node's full firmware | `ota config serve delta` |
| Trust a signer | `ota key add <hex>` |
| Update this node to one update (download + install) | `ota update <mid>` |
| Allow signed updates to be pushed to this node | `ota config push trusted` |
| Push an update to one remote node | `ota nudge <pubkey> <mid>` (or `motatool serve … --nudge <pubkey>`) |
| Keep an update on this node for others (no computer needed) | `ota host <mid>` (then `ota host nudge <pubkey>`) |
| Relay a folder (gateway) | `ota folder on` + the seeder daemon |
| List what I'm offering | `ota folder` |

(Older names still work too: `neighbors`/`updates` = `ls`, `pull` = `get`, `applydelta`/`apply` = `install`, `drop`/`stop` = `cancel`.)

---

## A few terms

- **Firmware** — the software running your node. Updating it can add features or fix bugs.
- **`.mota`** — a packaged firmware update file, with built-in integrity checks.
- **Target** — your node's hardware + role identity. Your node only auto-fetches updates built for the
  same target, so it won't grab firmware meant for a different board.
- **Delta** — a small update containing only the changes from your current firmware (faster to send than a
  full image). Your node rebuilds the complete firmware from it and verifies the result before installing.
- **Signed** — the update carries the author's cryptographic signature, so you can verify who made it.

For the full technical details (the file format and the radio protocol), see
[the OTA protocol spec](ota_protocol.md).
