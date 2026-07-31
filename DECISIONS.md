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

## Phase 6 — Archives, Auto-Execution, Authenticode

### Archive inspection (`scanner/archive.rs`)

The largest remaining gap: a ZIP containing `invoice.pdf.exe` scored **zero**.
The archive is a well-formed ZIP, its entropy is normal for compressed data,
and `structure.rs` deliberately does not flag executables inside archives. Every
check looked at the container and none looked at the contents.

**Central directory only, never decompression.** A ZIP records each entry twice
— a local header before the data and the central directory at the end. The
central directory is authoritative (it is what extractors read) and gives every
name, size and flag for the cost of a seek. Three consequences, all deliberate:
a decompression bomb cannot be triggered by a scanner that never inflates
anything; the ratio that *identifies* a bomb is in the header already; and
memory stays proportional to entry count, not payload size.

**Bounds.** 16384 entries walked, 1024-byte names. The declared entry count
steers the loop but never sizes an allocation — it is attacker-controlled.
EOCD search window is 65535+22 bytes, which is the complete space the format
allows (the comment length is 16 bits), not a heuristic.

**Thresholds and why:**

| Signal | Risk | Reasoning |
|---|---|---|
| Path traversal (zip-slip) | 0.8 | No archiver produces `../` components. No benign case to trade against. |
| RLO/bidi character in entry name | 0.85 | Reverses displayed text so `.exe` renders as `.pdf`. Never legitimate in a filename. |
| Double extension inside | 0.75 | The case the module exists for. |
| Encrypted entries | 0.5 | Legitimate, but it is the standard way to defeat *all* content scanning — ours and Defender's. |
| Zip bomb | 0.6 | Requires **both** ≥100:1 ratio **and** ≥1 GB expanded. |
| Executable entries | 0.15–0.6 | Weak. Archives legitimately contain programs. |
| Delivery shape (≤3 entries, executable at root) | +0.3, capped 0.7 | A lone runnable file in an otherwise empty archive. |
| Archive wearing a document extension | 0.7 | Two disguises at once. |

**Zip bomb needs both conditions.** Ratio alone is a false-positive machine — a
10 KB file of zeros compresses ~1000:1 and is harmless. Absolute size alone
flags every large legitimate archive. Only enormous expansion *from almost
nothing* has no benign explanation.

**Executables inside archives stay weak.** This preserves the Phase 3 decision
rather than reversing it. An installer is an archive containing programs; a
malware drop is an archive containing *one* program at the root and nothing
else. The shape carries the signal, not the presence.

### Auto-execution surface (`scanner/autoexec.rs`)

Reframes the question from "does this look malicious?" to **"what happens if
the user double-clicks it?"** — which is the owner's stated goal and is far
more answerable.

**Weights reflect how unusual the format is, not how dangerous.** `.exe` is the
most capable format here and carries one of the lowest weights (0.2), because
downloading a program is the most ordinary transaction on the internet. `.pif`
scores 0.65 for the opposite reason: nothing has legitimately produced one in
decades, and it survives only because Windows still honours it. Getting this
backwards would flag every software download and miss the formats that matter.

**`.lnk` files are parsed, not just named.** A shortcut carries its command line
in plain text; reading it costs nothing and says exactly what would run. A
shortcut invoking a LOLBin scores 0.7, rising to 0.9 with concealment markers
(`-enc`, `-w hidden`, `DownloadString`). Verified against 41 real shortcuts from
the user's Recent folder: 40 parsed, none falsely accused.

**Office macros keyed on the format's own promise.** The `x` in `.docx` *means*
macro-free — Microsoft split the extensions precisely so the name answers the
question. A `.docx` containing `vbaProject.bin` therefore contradicts itself
(0.75, Critical), while a `.docm` doing the same is declaring what it is (0.45,
Medium). Legacy `.doc`/`.xls` are OLE compound files with no such distinction,
so the `_VBA_PROJECT` stream name is matched as UTF-16LE in the first 1 MB
(0.5).

**Disc images explain the Mark of the Web.** `.iso`/`.img`/`.vhd` score 0.5 and
the finding says why: files opened from a mounted image do not inherit the MOTW
that triggers SmartScreen and Protected View. That bypass is the entire reason
malware moved to this container, and it is the kind of thing a user cannot be
expected to know.

### Risk combination: archive and autoexec join by MAX, not sum

Phase 3 established "max within `whole_file_scan`, sum across streaming and
whole-file", justified by *overlap* — a packed executable trips entropy and PE
checks for one underlying fact.

Archive and auto-execution analysis do **not** overlap that way; they read the
ZIP index and the filename rather than the container, so summing would have
been defensible. They join by max anyway, for a different reason: every check
that identifies a real attack is already calibrated to be decisive alone
(0.7–0.85), while the weak ones (an archive contains a program; a document has
a macro) are weak *precisely because they are common and usually benign*.
Adding those is how a legitimate installer accumulates its way past the block
threshold. A false positive on ordinary software costs more than the compound
case buys.

### Authenticode (`scanner/signature.rs`) — the first NEGATIVE contribution

**This is the only check that can lower a score, and that makes it the only one
that is an evasion target.** Code-signing certificates are stolen and abused
routinely. If a signature buys a fixed discount off any detection, then signing
your malware is a way to purchase a lower risk score — inverting the point of
the whole scanner.

**The withholding rule** (`apply_trust_credit`, one place, heavily tested):

1. The credit is capped at **0.25** (`MAX_TRUST_CREDIT`).
2. It is **withheld entirely when any Critical or High finding is present.**
3. It can never produce a negative score.

Rule 2 is the important one. A signature may settle a genuinely *ambiguous*
file — the difference between "sandbox this" and "release it" — and nothing
more. It can never argue away strong evidence. Verified end to end: a genuinely
Microsoft-signed `kernel32.dll` renamed `invoice.pdf.exe` scores 0.8, undiscounted.

The cost is accepted knowingly: a signed, legitimately-packed installer stays in
the sandbox band rather than being released. That is the fail-closed direction,
consistent with the rest of the project.

**Asymmetry in the other direction.** A *broken* signature is strong evidence
(`TRUST_E_BAD_DIGEST` → 0.8, Critical): someone modified a signed program, which
has no innocent explanation. Expiry is deliberately mild (0.15) because
certificates expire and old software keeps working — treating that like
tampering would be wrong. Unsigned is 0.2, weak, because signing costs money and
plenty of legitimate software skips it.

**No network, ever.** `WTD_REVOKE_NONE` + `WTD_CACHE_ONLY_URL_RETRIEVAL`.
Revocation checking fetches CRLs and OCSP responses, which in a download scanner
means an unbounded stall mid-download and a scanner that behaves differently
online and offline. **The accepted cost is that a revoked certificate still
verifies** — and since revocation is how stolen certificates are usually dealt
with, that is precisely the case we cannot see. Third reason the credit is small.

**Catalog signing was NOT optional.** Verifying embedded signatures only,
`notepad.exe`, `cmd.exe` and `calc.exe` all reported **Unsigned** — because most
of Windows is signed by listing hashes in separate signed catalog files, not by
embedding a signature in each binary. Only `kernel32.dll` of the four had an
embedded signature. Reporting a signed system binary as unsigned is a
confidently-incorrect claim, so `CryptCATAdmin*` + `WTD_CHOICE_CATALOG` was
added, and the catalog's *own* signature is verified — a hash appearing in a
catalog proves nothing until the catalog itself is checked. All four now verify.

**Known asymmetry between the two signature types.** Modifying an
*embedded*-signed file yields `Tampered` (0.8). Modifying a *catalog*-signed
file yields `Unsigned` (0.2), because there is no embedded signature to
invalidate — the hash simply matches nothing. That is the honest report and a
genuinely weaker signal. Pinned by a test so it stays a known property rather
than a surprise.

### Testing against reality, not against our own encoder

Every ZIP fixture in `archive.rs` is built by the test module that consumes it,
which proves the checks work against *our understanding* of the format. That is
exactly the class of bug this project keeps hitting. `tests/real_containers.rs`
therefore hands the scanner archives written by `Compress-Archive` and .NET's
`ZipFile`, shortcuts written by Explorer, and binaries signed by Microsoft.

**Tests that cannot run must not look like tests that passed.** The first
version of the Office-document check swallowed read errors with a bare
`continue` and reported "no documents found" — a clean pass while checking
nothing. The cause was `os error 362`: every document in `OneDrive\Documents` on
this machine is a cloud placeholder with no bytes on disk. The test now counts
"found", "unreadable" and "checked" separately and prints all three.

(Downloads is `C:\Users\yadhu\Downloads`, outside OneDrive, so quarantine is not
affected by this. If a user ever has OneDrive backing up Downloads, the
whole-file pass would degrade to streaming-only and say so in the verdict.)

---

## Phase 3 — Scanner Suite

### UTF-16 blindness (the biggest single detection gap)

`intent.rs` scanned only `String::from_utf8_lossy`. Windows PE files store wide
strings as UTF-16LE, where `CreateRemoteThread` is `43 00 72 00 65 00 ...` and
lossy-decodes to `C<FFFD>r<FFFD>e...`, matching nothing. Since the red-flag
table is overwhelmingly Windows API names, the scanner was blind to most of
what it targets.

Now scans three views: lossy UTF-8, plus UTF-16LE at both byte alignments (a
chunk boundary can land mid-character). Matches are attributed to the encoding
that found them.

**Decision:** non-text byte pairs decode to NUL rather than being skipped.
Skipping would splice unrelated fragments together and manufacture matches not
present in the file - `Create` + binary gap + `RemoteThread` must not become
`CreateRemoteThread`. A test asserts exactly that.

### New modules

- **`structure.rs`** - data after a format's logical end (PNG `IEND`, ZIP EOCD
  with its comment-length field, JPEG `FFD9`, GIF trailer, PDF `%%EOF`),
  executables embedded inside opaque media, and double extensions
  (`invoice.pdf.exe`).
- **`entropy.rs`** - Shannon entropy overall and per 4KB sliding window.
- **`pe.rs`** - W+X sections, virtual size far exceeding raw size, executable
  sections empty on disk, entry point outside every section, known packer
  section names.

### Threshold decisions

**Trailing data ignored below 64 bytes.** Alignment padding is common; a
payload is not. Below that the false-positive rate would swamp the signal.

**Entropy is interpreted relative to the declared type, never absolutely.**
7.99 in a ZIP is correct; 7.99 in a `.txt` means it is not text. Compressed
formats are exempt outright - flagging them would fire on every legitimate
archive, image and Office document. Used naively, entropy is a false-positive
machine.

**Executables inside ZIPs are NOT flagged.** Archives legitimately contain
executables; flagging that fires on every installer. Only executables inside
*opaque media* (PNG/JPEG/GIF/BMP/RIFF) are suspicious, because those formats
have no legitimate reason to carry one.

### Risk combination: max within, sum across

`whole_file_scan` takes the **maximum** of structure/entropy/PE, because those
overlap heavily - a packed executable trips entropy AND PE section checks for
the same underlying fact, and summing would double-count it and push ordinary
packed software past the block threshold.

`combine()` **adds** streaming and whole-file scores, because those are genuinely
independent - "the extension lies about the type" and "a ZIP is appended after
the image data" are separate findings.

### Memory bound

Structure, entropy and PE analysis need the complete file, so they are the one
place memory is not flat. `chunking.max_whole_file_scan_bytes` (default 64 MB)
caps it. Larger files keep their full streaming scan and skip these checks, and
the verdict says so explicitly rather than implying a clean result.

### Static findings now survive the sandbox stage

Found by testing against the real samples: a file scoring into the sandbox band
was blocked with only `"Sandbox verdict: SUSPICIOUS. Behaviors: STUB..."` - the
static findings that sent it there were dropped from the user-facing verdict.
Since the detonation stub observes nothing, the static analysis is currently the
*only* part that observed anything, and it was the part being hidden. Verdicts
on the sandbox and detonation-error paths now carry the static signals too.

### Streaming booleans no longer discarded

`WatchOutcome` now carries `header_valid` / `extension_mismatch` /
`dangerous_intent` through to `risk::decide()`, replacing the
`..Default::default()` that silently reset them (open finding 13). They are
sticky - a signal raised by any span holds for the session, so a later clean
span cannot clear an earlier detection.

---

## Phase 2 — Interception Re-Architecture

**Problem:** Chrome exposes no API for a download's byte stream. The old design
worked around that by pausing the download and calling `fetch()` on the same URL
to obtain the bytes. Consequences, all real:

- the file was written to the user's actual Downloads folder regardless —
  `pause()` does not prevent that, and `resume()` completes it in place
- the URL was fetched **twice**, so the bytes scanned were not the bytes
  delivered. A server can serve benign content to the scanner and malicious
  content to the browser (TOCTOU). Bandwidth also doubled.
- POST-initiated, one-time-token, `blob:`, and auth-gated downloads cannot be
  re-fetched at all, so they were simply broken
- three separate error paths called `resume()`, releasing files **uninspected**
  exactly when the scanner was unavailable

**Decision:** `downloads.onDeterminingFilename` redirects every download into
`<Downloads>/aegis-quarantine/{uuid}.aegispart`. Chrome performs the single
fetch it was always going to perform — cookies, sessions, POST bodies and
one-time tokens keep working — and the host *tails the file as Chrome writes
it*. Nothing reaches the real Downloads folder unless `release::release()` puts
it there after a clean verdict.

Quarantine must live under Downloads because Chrome requires suggested
filenames to be **relative to the default download directory**; absolute paths
and `..` are rejected (verified against Chrome's documentation). This is a
constraint, not a preference.

**Every extension failure path now cancels**, never resumes: host unreachable,
port disconnected mid-scan, and any unexpected error all call
`chrome.downloads.cancel()`.

**Deliberate asymmetry:** Layer 1 (URL hover badge) fails **open** — never block
browsing because a local scoring service is down; it is an advisory badge, not a
gate. Layer 2 (file triage) fails **closed**. The safety property lives in
Layer 2 and it should not be weakened to match Layer 1's convenience.

### Trust boundary: `quarantine_path`

`WATCH_BEGIN` carries a path chosen by the extension. That crosses from the
browser into a process which will read the file and, on a clean verdict, **move
it into the user's Downloads folder**. Unvalidated, that is an arbitrary file
read and an arbitrary file move — a compromised extension could name
`C:\Windows\System32\config\SAM` and have Aegis relocate it.

`validate_quarantine_path()` canonicalizes both the claimed parent and the
quarantine root before comparing, so `..`, symlinks, junctions and 8.3 short
names cannot escape, and additionally requires the `.aegispart` suffix so the
host cannot be pointed at an unrelated pre-existing file in the directory.

### Interaction with Windows Defender (found by a failing test)

Writing EICAR to the quarantine directory caused `os error 225`
(`ERROR_VIRUS_INFECTED`) when the watcher tried to open it: **Defender's
real-time protection quarantined the file first.**

This is correct behaviour by Defender and the user is protected, but Aegis must
not treat it as a crash. `ScanStep::ExternallyQuarantined` maps it to a normal
BLOCK verdict naming the other product.

**Explicitly rejected:** adding a Defender exclusion for the quarantine
directory. That would disable real-time protection on the one folder guaranteed
to contain live malware, trading a genuine layer of defence for cosmetic
attribution of the block. Losing the race to Defender on signature-known malware
is the correct outcome.

This also sharpens the honest answer to "how is this different from Defender":
for known signatures Defender wins, and should. Aegis's contribution is the
**unknown sample** and the **pre-completion kill** — scanning as bytes arrive
and cancelling mid-transfer, which an on-write scanner by definition cannot do
because it acts once bytes are already on disk.

**Testing note:** on-disk tests must not use EICAR on a machine with Defender
active, or they measure Defender rather than Aegis. `watcher.rs` tests use real
high-risk signatures from the intent table (nc reverse shell, `/etc/shadow`,
`/dev/tcp`) instead.

---

## Target Browser Is Edge, Not Chrome (found in testing)

**Finding:** Google Chrome is not installed on the development machine at all.
The installed Chromium-family browsers are **Brave** and **Microsoft Edge**, and
the extension is loaded in **Edge** (its ID appears in
`%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Preferences`).

The installer registered the native messaging host only under
`HKCU:\Software\Google\Chrome\NativeMessagingHosts\` — a hive belonging to a
browser that does not exist here. Each Chromium browser reads **only its own**
hive, so `connectNative()` failed, no host process was ever spawned, and
`aegis-host.log` was never created.

The symptom was maximally misleading: the extension's fail-closed policy turned
"host not found" into "Aegis couldn't finish scanning this file", so **every**
download was cancelled, including obviously benign ones. Three genuine bugs were
found and fixed while chasing this (quarantine subdir drift, the
sharing-violation crash, MV3 session loss) — all real, none of them the cause.

**What actually settled it:** the absence of `aegis-host.log`. A missing log
distinguishes "the host ran and made a decision" from "the host was never
launched", and no amount of reading the code could separate those two.

**Decision:** the installer now enumerates Chrome, Chromium, Brave, Edge and
Vivaldi, registers under every hive whose browser is present, verifies each
write by reading it back, and reports which browsers were registered. It also
searches all of their profiles when auto-detecting the extension ID.

**Note for the spec:** `AEGIS_BUILD_SPEC.md` §8 lists cross-browser support as
out of scope, "Chrome MV3 only". That remains true of the *extension* — but host
registration must still target whatever browser is actually installed, or the
project cannot be run at all on this machine. Registering broadly costs nothing;
assuming Chrome cost several hours.

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

---

# Phase 6 — Archive, Auto-execution, Authenticode; detonation dropped

## Detonation dropped (supersedes every earlier sandbox decision)

The restricted-process sandbox was started, then removed rather than finished.
The HCS decision above explains why HCS could not work on this machine; this
explains why its replacement was abandoned too.

**Defender already does this, better and elsewhere.** Cloud-delivered protection
with Block-at-First-Sight holds an unknown file while Microsoft's cloud actually
detonates it, on Microsoft's hardware, with instrumentation and a malware corpus
no local implementation can match.

**A user-mode sandbox produces weak evidence.** A restricted process shares the
Windows kernel. It contains commodity malware, but it does not stop a kernel
exploit, and malware that fingerprints sandboxes simply behaves for the thirty
seconds it is watched. The samples worth worrying about are exactly the ones it
tells you least about.

**Building it means running unknown malware on the user's own machine** to
obtain that weak evidence. The half-built implementation did not even block
network access.

**The decisive argument is what it would replace.** With no detonation, an
ambiguous file is simply not delivered — a safe default. A sandbox introduces a
mechanism that can return `Clean`, and `decide_after_sandbox` mapped `Clean` to
`Release`. Swapping a safe default for a mechanism that can release a file
static analysis found suspicious is a net reduction in safety.

**Authenticode does the same job better.** The purpose of the middle band is to
resolve ambiguity. A binary signed by a real publisher resolves out of that band
statically, with no execution and no risk.

**Decision:** delete `src/sandbox/` entirely rather than leaving a stub. A stub
implies a stage that is coming; its absence is the design. `Decision::Sandbox`
is renamed `Decision::Inconclusive` for the same reason — the old name described
a step that no longer exists, and the verdict text it produced
(`Sandbox verdict: SUSPICIOUS. Behaviors: STUB...`) described the scanner's own
unfinished state rather than anything about the user's file.

Work preserved on `wip/phase4-restricted-sandbox`, unmerged.

---

## Archive inspection thresholds

The largest detection gap: a ZIP containing `invoice.pdf.exe` scored **zero**.
The container is a well-formed ZIP, its entropy is normal for compressed data,
and `structure.rs` deliberately does not flag executables inside archives.

**Parse the central directory, never decompress.** A ZIP records every entry
twice; the central directory is the authoritative index. Reading it yields every
name, size and flag for the cost of a seek. This is not only cheaper — a zip
bomb cannot be triggered by a scanner that never inflates, and the ratio that
identifies one is a header field.

**Risk assignments, and the reasoning for each:**

| Finding | Risk | Why |
|---|---|---|
| RLO in an entry name | 0.85 | No legitimate use. Reverses displayed extension. |
| Zip-slip traversal | 0.80 | No archiver produces this. Never accidental. |
| Double extension inside | 0.75 | The case this module exists for. |
| Zip bomb | 0.60 | Both conditions required (below). |
| Encrypted entries | 0.50 | Legitimate, but the standard AV-evasion move. |
| Lone root executable | up to 0.70 | The delivery *shape*, not the content. |
| Executable present | 0.15 | Reported, not accused. |

**"Contains an executable" is deliberately near-zero.** An archive containing a
program is what an installer *is*. Flagging it would fire on every software
download and destroy the signal-to-noise ratio. A test asserts an ordinary
installer archive stays below `sandbox_threshold`; if that test ever fails, the
check has become a false-positive generator.

**Zip bombs require BOTH a ratio >= 100:1 AND >= 1 GB expanded.** Ratio alone is
a false-positive machine — a 10 KB file of zeros compresses about 1000:1 and is
entirely harmless. Absolute size alone flags every large legitimate archive. It
is the combination, enormous expansion from almost nothing, that has no benign
explanation.

**Encrypted entries are reported but not decisive.** People do legitimately
password-protect archives. But nothing can scan inside one — not Aegis, and not
Defender either — which is precisely why malware campaigns ship them with the
password in the email body: it moves decryption to a human, past every automated
check. Reported as *unscannable*, never as *clean*.

---

## Auto-execution surface

Directly on the stated goal: stop files that execute on arrival.

**Extension weights are relative to how directly the format runs.** `.exe` is
0.15 inside an archive (installers are normal) while `.lnk` is 0.6, because a
shortcut carries an arbitrary command line behind any icon it likes and has no
reason to arrive in a download. Encoded script variants (`.jse`, `.vbe`) score
above their plain forms: encoding serves no purpose except concealment.

**Macros are judged against the declared format.** `vbaProject.bin` inside a
`.docm` is reported and not condemned — the user asked for a macro-enabled
document. The same stream inside a `.docx` is Critical, because that format is
macro-free by definition and the mismatch is deliberate.

---

## Authenticode: MAX_TRUST_CREDIT = 0.25, withheld on serious findings

The first and only signal that can *lower* a score, which makes it the first one
an attacker would want to trigger.

**Capped at 0.25** — enough to move a file from the inconclusive band to
release, nowhere near enough to rescue one that tripped a real detection.

**Withheld entirely when any Critical or High finding is present.** This is the
load-bearing rule. Without it, signing your malware buys down a real detection:
a packed dropper with a stolen certificate would score *lower* than the same
dropper unsigned, inverting the point of the check. A signature can settle an
ambiguous file; it can never argue away a strong one.

**A broken signature scores 0.8.** `TRUST_E_BAD_DIGEST` means the bytes changed
after signing. Unlike a valid signature, this has no innocent explanation.

**No revocation checking** (`WTD_REVOKE_NONE`, `WTD_CACHE_ONLY_URL_RETRIEVAL`).
Fetching CRLs and OCSP responses would stall a download for an unbounded time
and make the scanner behave differently online and offline. **The cost is that a
revoked certificate still verifies** — which is a third reason the credit is
small, and belongs in the docs rather than being quietly accepted.

**Catalog signing is checked**, because most Windows system binaries carry no
embedded signature and an embedded-only check reports `notepad.exe` as unsigned.

---

## Score combination: max across the new analyses too

`whole_file_scan` already took the maximum of structure/entropy/PE because those
overlap. Archive, auto-execution and signature analysis genuinely do *not*
overlap with them — they read the ZIP index, the filename and the certificate
respectively — so summing would be defensible.

**Max was chosen anyway, for a different reason.** Every check that identifies a
real attack is already calibrated to be decisive alone (0.7–0.85). The weak ones
— "this archive contains a program", "this document has a macro" — are weak
precisely because they are common and usually benign. Summing those is how a
legitimate installer accumulates its way past the block threshold, and a false
positive on ordinary software costs more than the compound case buys.

---

## Quarantine hardening was protecting the wrong directory

**Found while removing dead code, not by a test.** Phase 1 held samples in
`<temp>/aegis_quarantine/` and that is what `apply_windows_acl` locked down.
Phase 2 moved them to `<Downloads>/aegis_quarantine/`, created with a bare
`create_dir_all`. So the carefully secured directory held nothing, and the
directory holding every live sample inherited whatever permissions the user's
Downloads folder carried.

DECISIONS.md item 5 claimed a property the code no longer had on the path that
mattered — exactly the documentation drift this file exists to prevent.

**Decision:** `Quarantine::secure` takes the path explicitly rather than
deriving it, so there is one way to name that directory and one place that locks
it. Applied per session as well as at start-up, because anything can delete the
directory between sessions and a recreated one would inherit Downloads'
permissions again.

---

## The retired chunk protocol was still reachable

`handle_download_session` (~400 lines) served `START_DOWNLOAD`/`CHUNK`, which the
extension has not sent since Phase 2. It was unreachable in practice and still
carried the **pre-Phase-2 policy**: its `Release` branch told the extension to
perform the download itself, which is the TOCTOU architecture Phase 2 existed to
remove.

**Decision:** delete it, and refuse both message types explicitly rather than
letting them fall through to "unknown message type". If a future extension ever
regressed to sending `START_DOWNLOAD`, the worst outcome would be the host
quietly accepting it.

Six integration tests were exercising that protocol. **Three of them were
passing only because every chunk was now rejected** — green for the wrong
reason, which is worse than red. Rewritten against the live path.

---

## No HTTP client, and no network capability at all

`cargo audit` (run for the first time) reported RUSTSEC-2025-0134,
`rustls-pemfile` unmaintained, reached only through `reqwest` — which existed
for a single call forwarding URLs to a phishing model that is **out of scope for
Aegis** and whose weights are not in this repository.

**Decision:** remove it. `CHECK_URL` still answers, with `unscored` — identical
to its behaviour on any machine where no scoring service runs, which is every
machine so far, and the extension already renders that as a neutral badge.

```
dependencies   187 -> 92 crates
cargo audit    1 advisory -> clean
network        no outbound capability at all
```

The last line is the real gain. A file scanner with no network stack is a better
thing to have on a machine than one carrying an HTTP client it does not use.

Also dropped `futures-util`, `async-trait`, `tokio-util` and `base64` (zero uses
after the chunk protocol went), and narrowed `tokio` from `"full"` to the five
features actually used. The dependency tree of a process that parses hostile
input and writes into Downloads is attack surface, not an implementation detail.

---

## Filename sanitisation: safety without an ASCII allowlist

`sanitize_filename` replaced every character outside `[A-Za-z0-9._-]` with `_`.
Safe — and it turned `Résumé.pdf` into `R_sum_.pdf`, `report (final).pdf` into
`report__final_.pdf`, and any filename not written in English into a row of
underscores. Aegis is supposed to be invisible when a file is fine.

**Safety never required an allowlist, only that specific characters go.** Now
removed by name: separators and `..`, control characters, the characters Windows
forbids (`:` most of all — `notes.txt:payload.exe` is an NTFS alternate data
stream), trailing dots and spaces (Windows strips them, so `evil.exe.` opens as
`evil.exe`), and bidirectional overrides.

That last one closed a real gap: `archive.rs` reports U+202E inside a ZIP as
Critical, but nothing stopped the identical trick surviving into a *released*
filename, where no check looks for it.

**The doubled extension in HANDOVER 6.6 is not a bug.** Chromium chooses that
name from the response MIME type; reproducing it is what the user would have got
without Aegis. Documented rather than "fixed".

---

## The prototype was a malware executor

`aegis/src/hcs.rs` contained `start_behavioral_scan`, which renamed the
downloaded file to `sandbox_exec.exe` and ran it via `Command::spawn` with **no
isolation of any kind**: full user token, full privileges, network reachable, no
job object, no integrity drop. Its scoring could not reach its own threshold
(maximum 10, tested `> 10`), so it executed malware and then reported clean.

Unreferenced by any build, but 22 MB of loaded gun in the repository. Having
just declined to build an *isolated* sandbox on the grounds that running malware
locally is a bad trade, keeping an unisolated one was indefensible.

**Decision:** deleted. Along with `test_memory.py`, `test_trojan_file.py` and
`test_ipc.py`, all three of which drove the retired protocol.

---

## Fuzzing: mutation harness, not cargo-fuzz

Spec §4 requires fuzzing. Coverage-guided fuzzing is strictly better at finding
deep bugs and needs a nightly toolchain plus libFuzzer, which is awkward on
Windows/MSVC.

**Decision: an in-repo deterministic mutation harness**, for two reasons.

These parsers are days old, so the bugs still in them are the shallow ones — a
forgotten bounds check, a trusted length — and blind mutation finds those
readily. Coverage guidance earns its keep on mature parsers.

And a `cargo-fuzz` run is an event someone has to remember to repeat. This runs
on every `cargo test`, and any parser added later is covered by adding one line
to `TARGETS`.

**The oracle is "no panic AND finished inside a time budget."** Hangs matter as
much as crashes: every parser bounds its loops, and a wrong bound means a
crafted file spins while the download sits open forever.

**Why a panic is not an ordinary crash here.** The host dying drops the native
messaging port; the extension correctly reads that as "cannot verify" and
cancels. So one crafted file does not infect anyone — it fails safe — but it
stops *every download on the machine* until the user works out why. That is a
denial of service triggered by a single download, and it is why §4 forbids
panics on any path.

41,200 cases per run. The one bug it found was in a test of mine, which had
asserted `is_err()` on a partial length prefix while its own comment said
"disconnect".

---

## Findings on the release path

`send_final_verdict` carried no findings, so for any file that **passed** the
user saw nothing. That made "Signed by Microsoft Corporation" unreachable: a
signed file is released, so it never touches a block path, and the entire
user-visible payoff of Authenticode could never be delivered.

**Decision:** releases carry findings too, plus a provenance clause naming the
signer. An unsigned executable is called out on release as well — it passed, and
the user is about to run something whose origin nobody can vouch for, which is a
fact about the file rather than an accusation against it.

The popup labels the section by outcome — "Notes on this file" when delivered,
"Why this was not delivered" when not — because rendering a signature
identically to a block reason would make every cleared download look like a near
miss.
