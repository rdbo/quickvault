# Synthetic preview fixtures

Generated locally with FFmpeg 9.0.2 for plan0050; no user content. These files
are embedded only in the `validation` feature, then imported through real core
attachment encryption. Builds consume the checked-in bytes and need no FFmpeg.
The 8 MiB silent WAV is generated as a bounded reader at runtime, within the existing10 MiB per-file limit.

- `preview.mp4`: four seconds of `testsrc=size=128x96:rate=12`, H.264/yuv420p,
  plus `sine=frequency=440:sample_rate=22050` at 1% amplitude, AAC, faststart.
  SHA-256: `e4643a1a075bc54edca1fb12f406a314275918fec23b8ce1e67858a5263f524d`.
- `preview.png`: one blue 64×32 RGB PNG.
  SHA-256: `86784280e71c3efcebfce00ccca654157d2d5b02778cc07daad8b7dd9d6eef5a`.
- `large-preview.png`: one black 5000×4000 RGB PNG; its RGBA lower bound is
  80,000,000 bytes. The engine test verifies that it is deferred before decoding.
  SHA-256: `353a0ff9a999605ba015fbc326f57549a07657d089969341df07272bcbf4c3b9`.

Generation uses FFmpeg's `lavfi` sources, `-map_metadata -1`, and `-threads 1`.
The MP4 uses `-t 4 -c:v libx264 -pix_fmt yuv420p -c:a aac -af volume=0.01
-movflags +faststart`; PNG sources use `color` and `-frames:v 1`.
