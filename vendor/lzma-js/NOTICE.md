`lzma-c.js` is the compress-only build of LZMA-JS 2.3.2 by Nathan Rugg (MIT, see `LICENSE`), from
`https://registry.npmjs.org/lzma/-/lzma-2.3.2.tgz` (SHA-256 `8bdab21a2d4f108f85c500fde1a632d0d859eba71f14cc921d60d7c5c99b8f68`),
a JavaScript port of Igor Pavlov's LZMA SDK (public domain).

MeshCore changes (marked `/// MeshCore`): a mode object may carry `lc`/`lp`/`pb` (upstream fixes them to 3/0/2),
`get_mode_obj` accepts a custom mode object (used for the 4 KB dictionary), and the module is exported for the
page, its Web Worker and Node instead of `this.LZMA`.
