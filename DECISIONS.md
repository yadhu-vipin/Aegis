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

## HCS Removed Entirely (supersedes the Phase 4 HCS decision below)

**Finding:** this machine is Windows 11 **Home** Single Language. `vmcompute.exe`
is absent and `Microsoft-Hyper-V-All`, `Containers`, `VirtualMachinePlatform`
all report `NOT AVAILABLE ON THIS EDITION`. HCS cannot run here at all, and
enabling it requires a paid upgrade to Pro.

`ComputeCore.dll` *is* present, which is why the code appeared plausible — it
would have linked and then failed at runtime against a service that does not
exist.

The HCS code was also wrong independently of that. Verified against Microsoft's
API and schema reference, then confirmed by the compiler:
- `HcsCreateComputeSystem` takes **5** parameters (id, configuration,
  `HCS_OPERATION`, security descriptor, out-param). The code passed 3 and treated
  the return value as the compute system. → `E0061`, `E0308`.
- The API is **asynchronous**: `S_OK` means only that the operation *started*.
  Callers must create an operation with `HcsCreateOperation` and wait via
  `HcsWaitForOperationResult`. The code did neither.
- The config JSON set no `Container` / `VirtualMachine` / `HostedSystem`
  property, which the schema requires as mutually exclusive and mandatory. It
  put `GuestOs` / `Storage` / `Networking` / `Processor` / `Memory` at the top
  level, where they are all `Container` sub-fields.
- `Storage.ScratchVhd`, `CreateInstead` and `SizeInGB` are **not real schema
  fields**. `Storage` has exactly `Layers`, `Path`, `QoS`. So the "ephemeral
  VHDX diff disk" hardening requirement was never actually implemented — the
  `remove_file(&scratch_vhd)` cleanup deleted a file that was never created.
- The sample was never executed: no `HcsCreateProcess` call anywhere.
- **Fail-open verdict:** `HcsTerminateComputeSystem` returning `Err` mapped to
  `Verdict::Clean`, and `decide_after_sandbox()` maps `Clean -> Release`. Any
  HCS API failure released the file.

**Decision:** delete `sandbox/windows_hcs.rs` and drop the
`Win32_System_HostComputeSystem` Cargo feature. Detonation becomes
`sandbox/windows_restricted.rs` — restricted token, Low integrity, Job Object,
isolated desktop — which works on Home. Phase 1 ships it as a fail-closed stub
returning `Suspicious`; real isolation lands in Phase 4.

**Honest limitation to carry into the docs:** a restricted process shares the
kernel. It contains commodity malware but does not stop a kernel exploit or a
sandbox-escape chain, and sandbox-aware malware can simply behave while watched.
This is a weaker boundary than a VM and `ARCHITECTURE.md` must say so plainly.
Consequence: the strongest protection in this build is the streaming static
analysis plus the quarantine broker, not the detonation stage.

---

## Hardening Pass — Findings and Status

**FIXED in Phase 1:**

1. **Truncation attack** (`main.rs`) — a mid-transfer pipe close `break`ed and
   then scored the *partial* file. Truncated files score low, so "send one
   benign chunk, then disconnect" reliably produced a `COMPLETE` verdict. Now
   tracked by a `transfer_completed` flag set only on `is_last`; anything else
   BLOCKS. **Fail-closed policy call.**
2. **Sequence numbers unvalidated** (`main.rs`) — `seq` was parsed and echoed in
   the ack but never checked, so out-of-order, duplicate, and replayed chunks
   were accepted and written in arrival order, letting an attacker control the
   byte layout of the quarantined file relative to what was scanned. Now
   enforced strictly against `expected_seq` starting at 0.
3. **Unbounded disk write** (`main.rs`) — `total_bytes` was accumulated but never
   checked. With no `Content-Length` the guard reserved ~25.6 MB and then
   accepted unlimited chunks. Added `chunking.max_download_bytes` (default 8 GB),
   enforced continuously inside the loop, validated at config load.
4. **Quarantine leak** (`main.rs`) — the post-sandbox `Release` path never deleted
   the quarantine file. Now deletes, matching the pre-sandbox path.
5. **Windows ACL never applied** (`quarantine.rs`) — previously a warning log only.
   Now applied via `icacls` with an argument array (no shell interpolation, per
   §4): inheritance stripped, single-principal full control. **FAIL CLOSED —
   host startup aborts if the quarantine directory cannot be secured**, on the
   grounds that scanning samples an attacker could swap underneath us is worse
   than not starting. Verified on disk: the directory carries exactly one ACE.
6. **`unreachable!()` panic landmine** (`main.rs`) — replaced with a fail-closed
   BLOCK branch. §4 forbids panics on any path; a panic in a security tool is an
   availability failure.
7. **`f_bavail * f_bsize`** (`quarantine.rs`) — POSIX defines `f_bavail` in units
   of `f_frsize`. Corrected, and the multiply is now `checked_mul`.
8. **Dead code in `sanitize_filename`** (`quarantine.rs`) — separators were
   filtered *before* the basename split, making the split dead and turning
   `a/b/evil.exe` into `abevil.exe` rather than `evil.exe`. Order corrected;
   `..` now collapses to `_` instead of discarding the whole name. Six unit
   tests added.
9. **Unused imports** — `ULARGE_INTEGER` (a real `E0432` compile error, not just
   a lint) and the three unused HCS imports (removed with the file).

**STILL OPEN — carried into later phases:**

10. **TOCTOU on release** (Phase 2) — `Decision::Release` deletes the quarantine
    copy and lets the extension perform the real download, so the bytes scanned
    and the bytes delivered are two separate fetches. The Phase 2 re-architecture
    removes this by having Chrome download straight into quarantine.
11. **UTF-16 blindness** (Phase 3) — `intent.rs` runs `from_utf8_lossy` over raw
    bytes, but PE files store API names as UTF-16LE, so `CreateRemoteThread`
    decodes to `C<FFFD>r<FFFD>e...` and never matches. The red-flag table is
    mostly WinAPI names, so the scanner is largely blind to what it targets.
12. **Ring buffer over-retention** (Phase 2) — retains `ring_buffer_chunks` full
    chunks (1 MB) but only the last 256 bytes of the newest are ever read.
13. **`aggregate_result` discards booleans** (Phase 3) — `..Default::default()`
    resets `header_valid` / `extension_mismatch` / `dangerous_intent`. Works only
    because `decide()` reads `risk_score` alone; fragile if that changes.

---

## Native Host Registration (Phase 1)

**Finding:** `install_native_host.ps1` registered
`allowed_origins: ["chrome-extension://aegisdownloadguardextensionid/"]`. Chrome
extension IDs are exactly 32 characters from `a`–`p`; that placeholder is 29
characters and contains `r`,`s`,`t`,`u`,`w`,`x`,`z`. It could never match a real
extension, so `connectNative()` would fail **silently** — no error, just nothing.

**Decision:** the script now takes `-ExtensionId`, validates it against
`^[a-p]{32}$`, and auto-detects from Chrome's `Preferences` by matching the
unpacked extension path when not supplied. It **refuses to install** with an
invalid ID rather than registering something that cannot work.

Also: the manifest is now written with `UTF8Encoding($false)` and verified
BOM-free. PowerShell 5.1's `Set-Content -Encoding UTF8` emits a BOM, which
Chrome's manifest parser can reject — another silent-failure mode.

The registry path `HKCU:\Software\Google\Chrome\NativeMessagingHosts\<name>` was
already correct (verified against Chrome's native messaging documentation); the
script now reads the value back after writing rather than assuming it took.

---

## Existing Code Migration Decision

The original `aegis/` directory (with `hcs.rs`, `scanner.rs`, `main.rs`) is
**replaced** by the new `aegis-host/` directory with the refactored structure
per the spec. The original files are not deleted but become dead code once the
new binary is the canonical build target.

Decision: rename existing `aegis/` → `aegis-host/` by rewriting in place.
