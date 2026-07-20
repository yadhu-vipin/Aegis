# DECISIONS.md — Aegis Build Log

This file documents every assumption and design decision made during the build.
Updated after each phase.

---

## ML Model Decision (Phase 2)

**Finding:** The `.pt` files in `URL/` (`url_gen_verbose_epoch_*.pt`) are
**Generator** checkpoints from a Wasserstein GAN trained in `newtrain.ipynb`.
They are not classifiers — they generate URLs conditioned on a label (0=benign,
1=phishing).

**The actual phishing *classifier* lives in `train.ipynb`** as
`MultiScalePhishNet` and its weights would be saved as
`phish_model_v2_deterministic.pth`. That file is **not present** in the repo.

**Decision:** Build the inference service around `MultiScalePhishNet`
(the classifier architecture from `train.ipynb`), loading the epoch-30 Generator
checkpoint (`url_gen_verbose_epoch_30.pt`) as a fallback discriminator-style
scorer via the Generator's internal discriminator (`G.state_dict()` checkpoint).
Since the GAN checkpoint only saves `G` (Generator), inference of phishing
probability will use the **Discriminator** approach from the GAN:
- Load the epoch-30 generator checkpoint (best available).
- Use the **vocabulary and char-to-int mapping** stored in the checkpoint
  (`char_to_int`, vocab_size=162) for preprocessing — this is exact.
- Reconstruct the `Discriminator` model from `newtrain.ipynb` and note that
  without a saved Discriminator checkpoint we cannot use it directly.

**Final Decision:** Implement `MultiScalePhishNet` classifier architecture from
`train.ipynb` with the following preprocessing (exactly as in notebook):
- Vocabulary: `"abcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;="`
- MAX_LEN: 200
- VOCAB_SIZE: 59 (58 chars + 1 padding)
- Tokenizer: lowercase, char-level, pad to MAX_LEN
- Model: Embedding(59,32) → 4× parallel Conv1d(kernels 2-5) → BiLSTM(64) → Sigmoid

Because the trained `.pth` weights are not present, the service will **start up
and warn** that no weights are loaded, returning a neutral 0.5 score with a
`"unscored"` label until the user runs `train.ipynb` and places
`phish_model_v2_deterministic.pth` in `ml-service/`. This is logged clearly at
startup and in every response header.

---

## Sandbox Platform Decision (Phase 1)

**Decision:** `linux_stub.rs` returns `Verdict::Suspicious` (fail cautious) with
a clear log line `"[STUB] Would detonate here on Windows HCS — returning Suspicious"`.
This lets the full pipeline be tested on Linux without silently passing all files.

---

## Chunking Architecture Decision (Phase 1)

**Decision:** Fixed chunk size = 262144 bytes (256 KB) as specified in spec.
Ring buffer = 4 chunks (1 MB window) for the intent scanner's cross-chunk context.
Per-chunk timeout = 30s. Total transfer timeout = 3600s (1 hour), configurable.

---

## Native Messaging IPC Decision (Phase 1)

**Decision:** The extension uses `fetch()` streaming + `ReadableStream` to stream
a file in 256KB chunks, each sent as a separate native-messaging frame
`{type:"CHUNK", session_id, seq, is_last, data: <base64>}`.
The host acks each chunk with `{type:"CHUNK_ACK", session_id, seq}` before the
extension sends the next, providing backpressure.

---

## Quarantine Path Decision (Phase 1)

**Decision:** Quarantine directory = `std::env::temp_dir()/aegis_quarantine/`.
Files named `{uuid}_{sanitized_filename}`. On Unix: `0700` permissions.
On Windows: restrictive ACL (Aegis service account only).

---

## Risk Thresholds (Phase 1)

**Default thresholds** (tunable via `aegis.toml`):
- `sandbox_threshold = 0.4` — risk score ≥ this triggers HCS detonation
- `block_threshold = 0.85` — risk score ≥ this blocks outright, skip sandbox
- `max_detonation_size = 262144000` (250 MB) — files larger skip live detonation
- `chunk_size = 262144` (256 KB)
- `ring_buffer_chunks = 4`

---

## Extension Layer 1 Decision (Phase 2)

**Decision:** Content script debounce = 150ms as specified. Cache TTL = 10
minutes. ML service URL defaults to `http://127.0.0.1:8787/score`. Fail open
(neutral "unscored" badge) if service unreachable within 500ms timeout.

---

## HCS Implementation Decision (Phase 4)

`windows_hcs.rs` uses the HCS API via the `windows` crate (Microsoft's official
Rust bindings) rather than raw `winapi` FFI. This is safer and more idiomatic.
The ephemeral VHDX diff disk approach uses `HcsCreateComputeSystem` with a
scratch VHDX discarded after each detonation. Network adapter not attached by
default.

---

## Existing Code Migration Decision

The original `aegis/` directory (with `hcs.rs`, `scanner.rs`, `main.rs`) is
**replaced** by the new `aegis-host/` directory with the refactored structure
per the spec. The original files are not deleted but become dead code once the
new binary is the canonical build target.

Decision: rename existing `aegis/` → `aegis-host/` by rewriting in place.
