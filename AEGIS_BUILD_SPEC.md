# AEGIS — Build Specification

> **How to use this file:** Drop this at the repo root as `AEGIS_BUILD_SPEC.md`. Then give your agent (Claude Code / Cursor / Antigravity) this single prompt:
>
> ```
> Read AEGIS_BUILD_SPEC.md fully before writing any code. Build the project exactly
> as specified, in the phase order given. After each phase, run the verification
> steps listed for that phase before moving to the next. Do not skip the Linux
> dev-mode stub — I am developing on Linux, target OS is Windows 11. Ask me nothing;
> make reasonable assumptions and document them in a DECISIONS.md file as you go.
> ```
>
> That's the only prompt you need. Everything the agent needs to build this end-to-end is below.

---

## 0. What This Project Is

**Aegis** is a two-layer, real-time endpoint download-safety system:

1. **Layer 1 — Link triage (before the click does damage):** A Chrome extension that, on link **hover**, runs a lightweight ML model against the URL and shows an inline risk indicator (safe / suspicious / dangerous) before the user commits to clicking.
2. **Layer 2 — File triage (as the download lands):** The same extension intercepts the actual download via Chrome's Native Messaging API, streams the file to a local Rust host process, which runs static checks (magic bytes, extension/content mismatch, heuristic intent scanning). Files that are **ambiguous or fail static checks** get detonated inside a **Windows HCS (Host Compute Service)** micro-container — never on the real filesystem — before being released to the user's Downloads folder.

Layer 1 and Layer 2 are independent and both always run. Layer 1 does not gate Layer 2, and vice versa — a "safe" link can still serve a malicious file, and a "suspicious" link's file still gets the same static + sandbox treatment.

**Target OS for the shipped product:** Windows 11 (HCS is Windows-only).
**Dev OS:** Linux. All Windows-only code must be behind `#[cfg(windows)]` with a working Linux stub so `cargo build`/`cargo check`/`cargo test` succeed on the dev machine.

---

## 1. Non-Negotiable Constraints

- Rust host must compile and pass `cargo check` on **both** Linux (stub sandbox) and be structured so it compiles on Windows without further refactor (agent will not have a Windows machine to test on — code review carefully instead of assuming it compiles).
- No panics on untrusted input. Every byte coming from the browser extension or from a downloaded file is untrusted — parse defensively, use `Result`, never `.unwrap()` on external data.
- No file is ever executed directly on the host OS. Anything that runs, runs inside HCS or not at all.
- Chrome extension targets **Manifest V3**.
- The ML model is a **pre-trained artifact** the project already owns (`url_gen_*.pt` files, notebooks in `train.ipynb` / `newtrain.ipynb`) — the agent should build an **inference wrapper** around it, not retrain it, unless explicitly asked.
- Everything must be independently runnable/testable without HCS available (i.e., on the Linux dev box), via the stub sandbox layer.

---

## 2. Final Directory Structure

```
Aegis/
├── AEGIS_BUILD_SPEC.md          # this file
├── DECISIONS.md                 # agent logs assumptions/decisions here as it builds
│
├── extension/
│   ├── manifest.json            # MV3
│   ├── background.js            # service worker: download interception, native messaging
│   ├── content_script.js        # hover detection + risk badge injection
│   ├── popup/
│   │   ├── popup.html
│   │   ├── popup.js              # shows recent verdicts, toggle protection on/off
│   │   └── popup.css
│   ├── native-messaging/
│   │   └── com.aegis.sandbox.json  # native host manifest, installed by setup script
│   └── icons/
│
├── ml-service/                  # Python inference microservice for the URL model
│   ├── inference_server.py      # FastAPI/Flask, exposes POST /score {url} -> {score, label}
│   ├── model_loader.py          # loads url_gen_*.pt, handles preprocessing
│   ├── requirements.txt
│   ├── train.ipynb              # existing, unchanged
│   └── newtrain.ipynb           # existing, unchanged
│
├── aegis-host/                  # Rust native messaging host
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs               # entrypoint: stdin/stdout native messaging loop
│       ├── ipc/
│       │   └── native_messaging.rs   # length-prefixed JSON framing per Chrome spec
│       ├── scanner/
│       │   ├── mod.rs             # deep_forensic_scan() orchestrator
│       │   ├── magic_bytes.rs     # scan_file(): file signature vs extension check
│       │   └── intent.rs          # detect_dangerous_intent(): heuristic content scan
│       ├── sandbox/
│       │   ├── mod.rs             # Sandbox trait (platform-agnostic interface)
│       │   ├── windows_hcs.rs     # #[cfg(windows)] real HCS implementation
│       │   └── linux_stub.rs      # #[cfg(unix)] dev-mode stub, logs + no-ops
│       ├── risk/
│       │   └── mod.rs             # combines static-scan score -> sandbox/no-sandbox decision
│       ├── quarantine.rs          # temp dir mgmt, uuid-named files, ACL (Windows) / perms (Unix)
│       └── config.rs              # paths, thresholds, loaded from aegis.toml
│
├── aegis.toml                    # central config: thresholds, paths, ML service URL
├── scripts/
│   ├── install_native_host.ps1   # registers native messaging host on Windows
│   ├── install_native_host.sh    # dev-mode registration on Linux (for testing IPC only)
│   └── build_release.ps1         # cargo build --release + packaging
└── docs/
    ├── ARCHITECTURE.md
    └── hcs_schema_reference.md
```

---

## 3. Streaming & Chunking Architecture (memory/storage independent)

Aegis must handle a 2KB installer and a 20GB ISO the same way, on a machine with 4GB RAM or 64GB RAM, without ever holding the whole file in memory or assuming the disk has room to spare. This governs the design of the entire download-interception pipeline.

**Core rule: nothing ever buffers a full file in memory or requires it to fully land on disk before scanning starts.**

- **Fixed chunk size, not proportional to file size.** Extension reads/forwards the download in fixed-size chunks (default `256 KB`, configurable in `aegis.toml`) via `chrome.downloads` + `fetch()` streaming (`ReadableStream`) rather than waiting for `downloads.onCreated` to report a completed file. Never accumulate chunks into one in-memory array before sending — forward each chunk to the native host as it arrives.
- **Streaming native messaging, not one giant message.** Chrome's native messaging has a **1MB message size limit per message** (and 4GB for host→extension in newer Chrome, but treat 1MB as the hard ceiling either direction to be safe) — this is a *forcing function* for chunking, not optional. Each chunk is its own length-prefixed native-messaging frame: `{type: "CHUNK", session_id, seq, is_last, data: base64}`. The host acks each chunk before the extension sends the next (simple backpressure — prevents a fast network from overwhelming a slow scanner).
- **Host-side bounded buffer, disk-backed beyond a small window.** The Rust host never holds more than a small ring buffer (e.g. last N chunks, default N=4 → 1MB window) in memory for the *intent/heuristic scanner* to look at sliding context across chunk boundaries. Everything else is written straight through to the quarantine temp file via a buffered `tokio::fs::File` writer — memory usage stays flat regardless of total file size.
- **Disk-space guard before accepting a download at all.** Before starting to write quarantine chunks, `quarantine.rs` checks available free space on the temp volume against the `Content-Length` header (if present) or a configurable max-accept size if unknown; if insufficient, the host replies with a `REJECTED_INSUFFICIENT_SPACE` verdict immediately rather than writing until the disk fills up. Never let an untrusted download exhaust host disk space.
- **Streaming scan, not "wait for 100% then scan.**" `scanner::deep_forensic_scan` is called per-chunk as already spec'd in §3.3 — magic bytes only need chunk 0, `detect_dangerous_intent` runs incrementally over each chunk plus the small trailing-context ring buffer so patterns split across a chunk boundary aren't missed.
- **HCS detonation of large files:** cap what actually enters the sandbox. If a file exceeds a configurable `max_detonation_size` (default 250MB — arbitrary/tunable, real malware droppers are rarely huge), skip live detonation and fall back to static-only verdict + a clear "too large to sandbox, proceed with caution" flag surfaced to the user, rather than trying to boot a multi-GB VHDX diff disk per download. Document this tradeoff plainly in `docs/ARCHITECTURE.md`.
- **Timeouts everywhere in the chunk pipeline**, not just at HCS detonation: a per-chunk read timeout and a total-transfer timeout, both configurable, so a stalled/slow-loris-style download can't hold a quarantine slot (and its disk space) open indefinitely.

---

## 4. Secure-Coding Requirements (applies to every component, not just Rust)

Aegis is, by definition, a program that processes hostile input by design — every line of parsing code here is attack surface. These are hard requirements, not suggestions, for the agent to follow while writing code:

**Rust host (`aegis-host/`):**
- No `.unwrap()`, `.expect()`, or array-index-without-bounds-check on anything derived from extension input, file bytes, or the ML service response. Use `Result`/`?` throughout; a malformed chunk should produce a clean `REJECTED_MALFORMED` verdict, never a panic that kills the host process (which would silently stop protecting the user).
- All size/length fields read from native-messaging frames or file headers are validated against sane bounds **before** being used to allocate, index, or seek — this is the classic integer-overflow-into-buffer-overrun class of bug (e.g., a claimed chunk length of `0xFFFFFFFF` must be rejected outright, never trusted to `Vec::with_capacity`).
- Filenames from the browser are never used directly as filesystem paths. Sanitize: strip path separators (`/`, `\`), `..`, null bytes, and reserved Windows device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`-`9`, `LPT1`-`9`) before using any part of the original name in the quarantine filename. The UUID prefix already spec'd in `quarantine.rs` means the sanitized original name is cosmetic only — never load-bearing for path safety.
- No shelling out to format strings built from untrusted data. If any process spawning is needed (e.g., invoking a scanning subprocess), use argument arrays (`Command::new(...).arg(...)`), never a single interpolated shell string.
- The native-messaging stdin/stdout channel is the trust boundary between "browser extension" and "privileged local host process" — treat every message from it exactly as skeptically as the host will later treat the file bytes themselves. Malformed JSON, unexpected message types, and out-of-order chunk sequence numbers must all be handled as rejections, not panics or silent misbehavior.
- Dependencies: pin versions in `Cargo.toml`, run `cargo audit` as part of the Phase 5 verification step and fix or document any flagged advisories.
- Quarantine files are deleted (not just marked-for-deletion) once a verdict is reached and the decision is acted on — no permanent accumulation of scanned payloads on disk beyond what's needed for the current detonation/verdict cycle, unless the user has explicitly enabled a "keep flagged samples" setting.

**Chrome extension:**
- MV3 CSP defaults apply — no `eval()`, no remotely-hosted script injection, no inline event handlers in any injected UI.
- The content script only ever reads `href` attributes and never executes or evaluates anything from the hovered page's DOM.
- Native messaging host manifest (`com.aegis.sandbox.json`) restricts `allowed_origins` to exactly the extension's own ID — never a wildcard.
- The local ML service call (`fetch` to `127.0.0.1:8787`) has a strict timeout and its response schema is validated (expected keys/types) before being used to render UI — never trust the local service blindly either, since a compromised or misconfigured local service is itself part of the threat model for a security tool.

**ML inference service (`ml-service/`):**
- Runs bound to `127.0.0.1` only, never `0.0.0.0` — this must never be reachable from the network.
- Input URL length capped and validated before feature extraction; reject absurdly long inputs rather than feeding them into the model unbounded.
- Model file loaded from a fixed, expected path only — no dynamic model-path-from-request-input, which would otherwise be an arbitrary-file-read vector.

**Verification step to add to Phase 5:** run `cargo audit`, `cargo clippy -- -D warnings`, and a fuzz pass (e.g. `cargo fuzz` target on `deep_forensic_scan` and the native-messaging frame parser specifically, since those two functions are the ones that see 100% of untrusted input) before calling the build ship-ready.

---

## 5. Component Specs

### 3.1 Chrome Extension — Layer 1 (Hover URL Check)

**File: `content_script.js`**
- Listen for `mouseover` on all `<a>` tags (debounce ~150ms so rapid mouse movement doesn't spam requests).
- On hover-hold, send `{type: "CHECK_URL", url: hoveredHref}` to the background service worker via `chrome.runtime.sendMessage`.
- On response, inject a small floating badge near the cursor: green "Verified safe", yellow "Use caution", red "Likely phishing" — with the numeric confidence score in a tooltip.
- Cache results per-URL for the session (`Map<url, {label, score, timestamp}>`, 10-minute TTL) so re-hovering the same link doesn't re-hit the model.

**File: `background.js`**
- On `CHECK_URL` message: forward to the local ML inference service (`http://127.0.0.1:8787/score` — configurable) with a short timeout (500ms). If the service is unreachable, fail open with a neutral "unscored" badge — never block browsing because the local service is down.
- On `chrome.downloads.onCreated`: this is Layer 2's trigger (see below).

**Manifest permissions needed:** `activeTab`, `downloads`, `nativeMessaging`, `scripting`, host permissions `http://127.0.0.1:8787/*` for the local ML service, and `<all_urls>` content-script injection (document this permission clearly to the user in the popup — it's the broadest one and deserves an explicit toggle to disable Layer 1 if the user doesn't want every page hover instrumented).

### 3.2 ML Inference Service — `ml-service/`

- Small local HTTP service (FastAPI recommended — lighter than standing up a full Rust ONNX runtime for a first version). Loads the `.pt` model once at startup.
- `POST /score {"url": "..."}` → `{"score": 0.0-1.0, "label": "safe"|"suspicious"|"phishing", "latency_ms": N}`
- Feature extraction for the URL model should live in `model_loader.py`, mirroring whatever preprocessing `train.ipynb` used — **agent must read `train.ipynb` and `newtrain.ipynb` first to reverse-engineer the exact feature pipeline** the weights expect (tokenization, char-level encoding, max length, etc.) rather than guessing. Mismatched preprocessing between training and inference is the single most common way these systems silently produce garbage scores.
- Runs as a background process launched by the Rust host on startup (or separately via a startup script) — document both options in `docs/ARCHITECTURE.md` and default to whichever is simpler to wire up given what's in the notebooks.

### 3.3 Rust Native Messaging Host — Layer 2 (File Triage)

**Native messaging framing (`ipc/native_messaging.rs`):**
Chrome's native messaging protocol prefixes every message with a 4-byte little-endian length. Implement a reader/writer over stdin/stdout following this framing exactly — this is a common bug source, get it right first since everything else depends on it.

**Download interception flow (`background.js` → host):**
1. `chrome.downloads.onCreated` fires → extension calls `chrome.downloads.pause()` or intercepts via `onDeterminingFilename` to hold the file before it's fully written to the user's real Downloads folder.
2. Extension streams the file bytes (or a reference/URL Chrome can refetch) to the native host via native messaging.
3. Host writes chunks into `quarantine.rs`-managed temp storage (never directly into the user's Downloads folder).
4. Host runs `scanner::deep_forensic_scan()` incrementally as chunks arrive.
5. Host computes a risk score (`risk/mod.rs`) combining: magic-byte/extension mismatch, heuristic intent flags, and (optionally) the same-family ML signal if useful for file content.
6. **Decision:**
   - Low risk → release file to Downloads immediately.
   - Ambiguous / failed static check → HCS detonation (`sandbox::detonate()`), then release only if detonation reports no malicious behavior; otherwise quarantine permanently and notify the user via the extension popup.
7. Host replies to the extension with the final verdict; extension resumes/completes or blocks the download accordingly.

**`scanner/mod.rs` — orchestrator:**
```rust
pub struct ForensicResult {
    pub header_valid: bool,
    pub extension_mismatch: bool,
    pub dangerous_intent: bool,
    pub risk_score: f32,
}

pub async fn deep_forensic_scan(
    chunk: &[u8],
    filename: &str,
    is_first_chunk: bool,
) -> anyhow::Result<ForensicResult> {
    let header_result = if is_first_chunk {
        magic_bytes::scan_file(chunk, filename)?
    } else {
        Default::default()
    };
    let intent_result = intent::detect_dangerous_intent(chunk)?;
    Ok(ForensicResult {
        header_valid: header_result.valid,
        extension_mismatch: header_result.mismatch,
        dangerous_intent: intent_result.flagged,
        risk_score: header_result.risk + intent_result.risk,
    })
}
```

**`sandbox/mod.rs` — platform trait:**
```rust
#[async_trait::async_trait]
pub trait Sandbox {
    async fn detonate(&self, binary_path: &std::path::Path) -> anyhow::Result<DetonationReport>;
}

pub struct DetonationReport {
    pub exit_code: Option<i32>,
    pub flagged_behaviors: Vec<String>,
    pub network_attempts: Vec<String>,
    pub verdict: Verdict,
}

pub enum Verdict { Clean, Suspicious, Malicious }

#[cfg(windows)]
pub use windows_hcs::HcsSandbox as PlatformSandbox;
#[cfg(unix)]
pub use linux_stub::StubSandbox as PlatformSandbox;
```

`windows_hcs.rs` implements this against the real HCS API (`HcsCreateComputeSystem` / `HcsStartComputeSystem` / guest telemetry collection). `linux_stub.rs` implements it as a no-op that logs "would detonate here" and returns `Verdict::Suspicious` by default (fail cautious, not fail open) — this lets the whole pipeline be tested end-to-end on the Linux dev box.

**HCS hardening requirements** (apply when implementing `windows_hcs.rs`):
- Ephemeral VHDX diff disk per detonation, discarded after.
- No network adapter attached by default; only attach an isolated, logged, egress-only network if explicitly testing for C2 callbacks.
- No clipboard/RDP redirection.
- Detonation timeout (default 30s, configurable in `aegis.toml`) — kill and mark `Suspicious` if it doesn't finish.

**`quarantine.rs`:**
- All temp files under `std::env::temp_dir()/aegis_quarantine/`, named `{uuid}_{sanitized_filename}`.
- Directory created idempotently; on Windows, apply a restrictive ACL at creation (only the Aegis service account can write). On Unix dev mode, `0700` permissions.

**`risk/mod.rs`:**
- Central place for the score → decision thresholds, pulled from `aegis.toml` so they're tunable without recompiling. Example:
```toml
[risk]
sandbox_threshold = 0.4   # score >= this -> HCS detonation
block_threshold = 0.85    # score >= this -> block outright, skip sandbox, notify user
```

### 3.4 Config — `aegis.toml`
Single source of truth for: ML service URL, quarantine path, risk thresholds, HCS detonation timeout, log level. `config.rs` loads and validates this at host startup; fail fast with a clear error if malformed rather than silently defaulting.

---

## 6. Build Phases (agent executes in this order)

### Phase 1 — Stabilization & IPC (get it compiling and talking)
- Fix the three known Rust issues: `winapi` behind `#[cfg(windows)]`, `deep_forensic_scan` orchestrator wired to existing `scan_file`/`detect_dangerous_intent`, hardcoded Windows paths replaced with `quarantine.rs`.
- Implement native messaging framing both directions.
- Stub sandbox returns a hardcoded `Verdict::Suspicious` with a log line.
- Implement the fixed-size chunk framing, bounded ring buffer, and disk-space guard from §3 now — this is foundational, not a later add-on.
- **Verify:** `cargo check` and `cargo build` succeed on Linux. A manual test script sends a fake native-messaging payload to the host binary over stdin and confirms a well-formed JSON reply on stdout. A second test script streams a synthetic multi-hundred-MB file through in chunks and confirms host RSS memory stays flat (bounded by the ring buffer, not the file size).

### Phase 2 — Extension + Layer 1 Hover Check
- Build `content_script.js` hover detection + badge UI, `background.js` messaging, `popup` UI.
- Stand up `ml-service/inference_server.py`, reverse-engineered from the notebooks' preprocessing.
- **Verify:** loading the unpacked extension in Chrome, hovering a known-safe and a known-malicious-looking test URL produces distinct badges. `curl -X POST localhost:8787/score` returns valid JSON.

### Phase 3 — File Triage Pipeline End-to-End (stub sandbox)
- Wire `chrome.downloads` interception through native messaging to the Rust host, through `deep_forensic_scan`, through `risk::decide()`, to the stub sandbox, back to a verdict shown in the extension.
- **Verify:** downloading a benign test file passes straight through; downloading a file with a deliberately mismatched extension/magic-byte (e.g., an `.exe` renamed `.jpg`) triggers the "would sandbox" path and the popup shows the flagged verdict.

### Phase 4 — HCS Integration (Windows-only, code-complete but untestable on Linux)
- Implement `windows_hcs.rs` for real, following the hardening blueprint in §3.3.
- Since the agent likely can't test this on the dev machine, prioritize **correctness against the documented HCS API surface** and clear inline comments on anything that needs manual verification on a real Windows box.
- **Verify:** code compiles when cross-checked with `cargo check --target x86_64-pc-windows-msvc` if a Windows toolchain is available; otherwise, thorough manual code review against `docs/hcs_schema_reference.md`.

### Phase 5 — Polish & Ship
- `install_native_host.ps1` registers the native messaging host manifest correctly for Chrome on Windows.
- Error states surfaced clearly in the popup (ML service down, host unreachable, detonation timed out).
- `docs/ARCHITECTURE.md` finalized with a real component diagram (mermaid is fine) and a short "how this differs from MDAG/Windows Sandbox/Bromium" section for portfolio/demo purposes.
- Run `cargo audit`, `cargo clippy -- -D warnings`, and a fuzz pass on `deep_forensic_scan` and the native-messaging frame parser per §4's verification step. Fix or explicitly document any findings.
- Test the chunking pipeline against both extremes explicitly: a ~1KB file and a multi-GB file (a large public Linux ISO works fine as a synthetic test), confirming host memory stays flat (check with `/usr/bin/time -v` or equivalent) across both, and that the disk-space guard from §3 correctly rejects a download when the temp volume genuinely lacks room.

---

## 7. What "Done" Looks Like

- A user can load the unpacked extension, hover any link on any page, and see a risk badge within ~500ms.
- A user can download any file; if it's flagly ambiguous by static checks, it visibly goes through a "scanning in sandbox" state in the popup before being released or blocked.
- The whole pipeline runs and is testable on Linux via the stub sandbox, with HCS as a Windows-only real implementation behind the same trait.
- `DECISIONS.md` contains a running log of every assumption the agent made (model preprocessing details, thresholds chosen, permission scope decisions) so these can be revisited later.

---

## 8. Explicitly Out of Scope (for this build pass)

- Retraining or improving the ML model's accuracy — treat the existing weights as fixed.
- A cloud/telemetry backend — everything is local-only for this version.
- Cross-browser support (Firefox/Edge) — Chrome MV3 only for now.
- Full ETW-based in-guest behavioral telemetry — Phase 4 ships with exit-code + basic file/network activity from HCS; deeper telemetry is a documented future enhancement in `ARCHITECTURE.md`, not built now.
