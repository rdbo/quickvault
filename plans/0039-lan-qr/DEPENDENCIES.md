# Plan 0039 dependency record

Three new registry packages; existing shipped dependency versions remain pinned.
The fuzz workspace gains the real app/core graph to exercise the actual decoder,
with UI features disabled. Its separate lockfile records that tool-only graph.

| Package | License | Role | Exact crates.io archive SHA-256 |
|---------|---------|------|--------------------------------|
| qrcodegen-no-heap 1.8.1 | MIT | Binary encoder with caller-owned buffers | d0e2c0bf8be8a1c4a4f48973dabf26943f05da2bfc2d3180aae62409dbba6f0c |
| quircs 0.10.3 | MIT | Grayscale QR detection and binary decoding | d71dee9e56835add6f9c26227e6c690b19eda9414f5affc666c3ec833ba140dc |
| num-derive 0.4.2 | MIT OR Apache-2.0 | quircs enum conversion proc macro | ed3955f1a9c7c0c15e092f9c887db08b1fc683305fdf6eb6684f22555355e202 |

Primary sources:
[qrcodegen-no-heap upstream](https://github.com/nayuki/QR-Code-generator/tree/master/rust-no-heap),
[API](https://docs.rs/qrcodegen-no-heap/1.8.1/qrcodegen_no_heap/),
[quircs upstream](https://github.com/dignifiedquire/quircs),
[quircs API](https://docs.rs/quircs/0.10.3/quircs/),
[num-derive upstream](https://github.com/rust-num/num-derive).
The encoder supports QR model 2 binary mode and all ECC levels. It needs no
registry dependencies. The decoder is a Rust quirc port; its other dependencies
(num-traits and thiserror) already exist in the product lockfile. No independent
audit report is claimed. These are established projects, not an assurance that
this composition is safe or adequately audited.

The alternatives considered were qrcodegen 1.8.0 (private heap-owned buffers),
rqrr 0.10.1 (private image buffers, g2p/lru graph), and Android ZXing/ML Kit
(extra JVM dependencies and/or service assumptions). No image-file codec,
bitmap/image crate, Play Services or cloud decoder is added.

Targeted source inspection, not a complete security audit:

- qrcodegen-no-heap's encode_binary uses supplied scratch and output slices.
  QuickVault supplies Version::MAX.buffer_len() protected buffers and <=1024
  input bytes, satisfying its documented assertions. The output is copied
  directly into a protected row-major symbol; both scratch allocations drop.
  No cryptographic primitive is implemented by either library.
- quircs identify/resize allocates width*height pixels. Its scan loops include
  unsafe unchecked indexing. QuickVault validates nonzero axes <=1024, checked
  multiplication, exact input length and <=786432 pixels before entering it.
  Bounds and immutable borrowed input prevent app-side length/dimension changes
  during the call. Candidate/code payload work is bounded by QR model 2.
- The adapter wipes exposed Quirc pixels, extracted cell bitmaps (including the
  extra ambiguous grid), and the returned payload buffer. It rejects multiple
  grids, non-byte/ECI output and >1024-byte payloads, then promptly protects the
  binary payload. The complete canonical core codec/profile/address policy
  still runs before form insertion. No decoder error text is retained.
- Internal decoder stack/scratch and camera/JVM/OS/framework intermediates have
  best-effort cleanup limits. Pixel/module data is secret when it encodes the
  pairing secret. SVG path construction reserves once and uses Zeroizing;
  the web engine's copies cannot be deterministically erased. Do not infer
  physical erasure or locked-device security from buffer drops.

Supply-chain policy uses the repository's existing owner-delegated development
baseline: exact safe-to-deploy **exemptions**, each explicitly recording audit
debt, for the three new packages. These are not audit certificates or release
approval. `cargo deny check` and `cargo vet --locked` pass with that debt visible;
no new license exception/advisory ignore or weakened source policy is needed.
Initial tool failures (missing tools/read-only default advisory cache, and direct
cargo-vet invocation without Cargo's environment) were resolved using tools in
`/tmp/qv-0039-tools`, Cargo invocation and an isolated advisory cache. No HOME or
system installation was changed.
