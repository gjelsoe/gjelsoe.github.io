/* Encoding worker: keeps the page responsive while bsdiff / LZMA run (seconds for a 1 MB image). */
self.MotaCore.init({ bsdiff: self.MeshCoreDetoolsBsdiff, pack: self.MeshCoreDetoolsPack, crle: self.MeshCoreDetoolsCrle,
  lzma: self.MeshCoreLzmaEncoder });
self.onmessage = (e) => {
  const { id, kind, from, to } = e.data;
  try {
    const out = kind === 'lzma' ? self.MotaCore.lzmaWrap(from)
      : kind === 'in-place' ? self.MotaCore.encodeInPlace(from, to) : self.MotaCore.encodeSequential(from, to);
    self.postMessage({ id, patch: out }, [out.buffer]);
  } catch (err) {
    self.postMessage({ id, error: String(err && err.message || err) });
  }
};
