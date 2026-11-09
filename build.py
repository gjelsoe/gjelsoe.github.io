#!/usr/bin/env python3
"""Assemble the single-file page tools/mota/web/mota_push.html from src/ + vendor/.

The page must work when opened straight from disk (file://) with no network, so every script is inlined:
  vendor/detools-js/*.js        (MIT, Ahmet Ucar; browser adaptation from mikecarper/MeshCore) — delta encoder
  vendor/noble-ed25519/index.js (MIT, Paul Miller, v2.3.0 from npm)                         — Ed25519
  src/mota_core.js                                                                         — .mota v3 + seeder
  src/page.js / src/page.html                                                              — UI + Web Serial

Usage: python3 tools/mota/web/build.py   (also writes dist/noble-ed25519.global.js for the Node tests)
"""
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))


def read(*p):
    with open(os.path.join(HERE, *p), encoding="utf-8") as f:
        return f.read()


def noble_global():
    """noble-ed25519 ships as an ES module; turn its single `export { ... }` into a global object."""
    src = read("vendor", "noble-ed25519", "index.js")
    m = re.search(r"export\s*\{([^}]*)\};?\s*$", src, re.S)
    if not m:
        raise SystemExit("noble-ed25519: export block not found (unexpected version?)")
    names = []
    for part in m.group(1).split(","):
        part = part.strip()
        if not part:
            continue
        if " as " in part:
            local, exported = [s.strip() for s in part.split(" as ")]
            names.append(f"{exported}: {local}")
        else:
            names.append(part)
    body = src[: m.start()]
    return "(function(){\n" + body + "\nglobalThis.nobleEd25519 = { " + ", ".join(names) + " };\n})();\n"


def main():
    os.makedirs(os.path.join(HERE, "dist"), exist_ok=True)
    noble = noble_global()
    with open(os.path.join(HERE, "dist", "noble-ed25519.global.js"), "w", encoding="utf-8") as f:
        f.write(noble)

    detools = "\n".join(read("vendor", "detools-js", n) for n in ("pack-size.js", "crle.js", "bsdiff.js"))
    detools += "\n" + read("vendor", "lzma-js", "lzma-c.js")   # LZMA-JS encoder (codec 3), page + worker
    core = read("src", "mota_core.js")
    # The worker gets the encoder + core only (no DOM); it is started from a Blob URL so file:// works.
    worker = detools + "\n" + core + "\n" + read("src", "worker.js")
    page = read("src", "page.html")
    def tag(js):
        return "<script>\n" + js.replace("</script", "<\\/script") + "\n</script>"
    scripts = "\n".join(
        tag(s)
        for s in (noble, detools, core,
                  "window.MOTA_WORKER_SRC = " + repr_js(worker) + ";",
                  read("src", "page.js"))
    )
    out = page.replace("<!--SCRIPTS-->", scripts)
    with open(os.path.join(HERE, "mota_push.html"), "w", encoding="utf-8") as f:
        f.write(out)
    print(f"wrote mota_push.html ({len(out) // 1024} KB)")


def repr_js(s):
    import json
    return json.dumps(s).replace("</", "<\\/")


if __name__ == "__main__":
    main()
