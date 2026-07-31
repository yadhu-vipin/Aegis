# Aegis — Handover

> **This file is descriptive, not aspirational.** Every claim here was verified by
> running the code. The older `CLAUDE_CODE_HANDOVER.md` at the repo root is the
> opposite — it describes an intended design and asserts work that was never done.
> Trust this file; treat that one as a design sketch.

**Read first:** this file, then `DECISIONS.md` (the audit trail of every
assumption and fail-open/fail-closed call). `AEGIS_BUILD_SPEC.md` is the
original spec — still useful for intent, but the architecture has since changed
in ways it does not reflect (see "Architecture" below).

---

## 1. What the project is, and what it is NOT

Aegis is a browser download broker. **Nothing reaches the user's Downloads
folder until it has been scanned and cleared.**

The goal, in the owner's words: *"not let files into the system which start
executing stuff as soon as it's downloaded."* It is **added security alongside
Windows Defender, not a replacement.** That framing matters — it decides what is
worth building. Aegis does not need its own signature database, cloud lookups,
or kernel driver. Defender has those. Aegis contributes two things Defender
structurally cannot:

1. **Pre-completion interception.** Defender's on-write scanner acts once bytes
   are on disk. Aegis scans as they arrive and cancels the download mid-flight.
2. **A hard quarantine boundary.** The file is never in the user's Downloads
   folder at any point unless it passed.

Layer 1 (URL/phishing ML) is a separate project and **explicitly out of scope**.

---

## 2. Current state — VERIFIED WORKING

The full pipeline runs end to end against real Microsoft Edge. Evidence from
`aegis-host/target/debug/aegis-host.log`:

```
# Executable renamed test_trojan.jpg
Magic byte scan detected="exe" claimed=jpeg
Intent flag "CreateRemoteThread" risk=0.6
Quarantined file discarded reason="early block"      <- never reached Downloads

# Legitimate 177 KB PDF
Download scan complete risk_score=0.0 decision=RELEASE bytes=177509
File released to Downloads to=...\IntroToObfuscation_Notes.pdf
```

**86 tests passing** (69 unit + 13 integration + 4 doc). `cargo clippy
--all-targets -- -D warnings` clean.

### Done

| Phase | What | State |
|---|---|---|
| 1 | Fail-closed fixes, HCS removal, native-host registration | done |
| 2 | Interception re-architecture, watcher, release broker | done, verified in Edge |
| 3 | UTF-16 intent, structure, entropy, PE + IAT, explained findings | done |

### Not done

| Phase | What |
|---|---|
| 4 | Restricted-process sandbox (`windows_restricted.rs` is a fail-closed stub) |
| 5 | `cargo audit`, fuzz targets, `ARCHITECTURE.md`, popup polish |

---

## 3. Architecture (as built — differs from AEGIS_BUILD_SPEC.md)

```
downloads.onDeterminingFilename
   -> suggest "aegis_quarantine/{uuid}.aegispart"
   -> Chrome does the ONE fetch (keeps cookies, session, POST, one-time tokens)
        |
        v
<Downloads>/aegis_quarantine/{uuid}.<ext chosen by Chrome>
        |
   extension --WATCH_BEGIN--> native host (com.aegis.sandbox)
        |
   host tails the growing file:
     magic bytes (first span) + intent strings (every span, UTF-8 AND UTF-16LE)
     score >= block_threshold  ->  EARLY_BLOCK  ->  downloads.cancel()
        |
   on completion: whole-file pass (structure, entropy, PE/IAT)
        |
   risk::decide() -> Release | Sandbox | Block
        |
   release.rs: move to Downloads, or delete
```

**Why not stream bytes from the extension?** Chrome exposes no API for a
download's byte stream. The only way an extension can supply bytes is to fetch
the URL a *second* time — which doubles bandwidth, breaks POST/token/auth
downloads, and means the bytes scanned are not the bytes delivered. The original
design did exactly that. Do not go back to it.

**Quarantine lives under Downloads** because `onDeterminingFilename` only
accepts paths relative to the default download directory. Absolute paths and
`..` are rejected by Chrome. This is a constraint, not a preference.

---

## 4. Things that WILL waste your time if you don't know them

These each cost hours. All verified.

1. **The browser is Microsoft Edge, not Chrome.** Chrome is not installed.
   Each Chromium browser reads native-host registrations only from its own
   registry hive. `scripts/install_native_host.ps1` handles all of them.

2. **The live host is `aegis-host/target/debug/aegis-host.exe`.** The manifest
   in play is `extension/native-messaging/com.aegis.sandbox.json`, which points
   directly at the build output — so `cargo build` makes changes live with no
   reinstall. **Its log is `aegis-host/target/debug/aegis-host.log`.** Copies at
   `C:\Aegis\` and `%LOCALAPPDATA%\Aegis\` are unused debugging leftovers.
   Reading the wrong log cost most of one session.

3. **Chrome rewrites the file extension.** You suggest `{uuid}.aegispart`;
   Chromium re-applies its own extension from the MIME type, so a PDF lands as
   `{uuid}.pdf`. `validate_quarantine_path` therefore validates a **UUID stem**,
   never the extension.

4. **Windows 11 Home has no Hyper-V.** `vmcompute` does not exist. HCS was
   removed for this reason and should not come back.

5. **Defender wins the race on known malware.** It quarantines EICAR in our
   quarantine dir before we can read it (`os error 225`). Handled as a normal
   BLOCK. Do **not** add a Defender exclusion for the quarantine directory —
   that would disable real-time protection on the one folder guaranteed to
   contain live malware. **Do not use EICAR in on-disk tests**; you will measure
   Defender, not Aegis.

6. **PowerShell 5.1 reads BOM-less `.ps1` as ANSI.** A single em-dash in a
   string literal produces nine cascading parse errors pointing nowhere near
   the real problem. Keep `.ps1` files pure ASCII.

7. **PowerShell needs `$env:LOCALAPPDATA`, not `$LOCALAPPDATA`.** The bash form
   silently resolves to `C:\Aegis\...`.

8. **Execution policy blocks scripts.** Use
   `powershell -ExecutionPolicy Bypass -File .\scripts\<name>.ps1`.

---

## 5. Key files

```
aegis-host/src/
  main.rs          native-messaging loop; handle_watch_session(); trust-boundary
                   path validation (validate_quarantine_path)
  watcher.rs       tails the growing download, early-kill logic, bounded memory
  release.rs       the ONLY path into Downloads; collision handling; stale sweep
  quarantine.rs    temp dir, ACL, disk guard, filename sanitisation
  risk/mod.rs      decide() / decide_after_sandbox() / aggregate_risk()
  config.rs        aegis.toml loading; fails fast, never silently defaults
  ipc/native_messaging.rs   4-byte LE framing, 1 MB bound, verdict senders
  scanner/
    mod.rs         deep_forensic_scan (per-span) + whole_file_scan + combine
    finding.rs     Finding { severity, title, detail, why } - the explanation layer
    magic_bytes.rs type vs extension
    intent.rs      red-flag strings, UTF-8 AND UTF-16LE
    structure.rs   polyglots, trailing data, double extensions
    entropy.rs     Shannon entropy, packing/encryption detection
    pe.rs          PE sections, packers, entry point, AND import-table (IAT) analysis
  sandbox/
    mod.rs         Sandbox trait, Verdict
    windows_restricted.rs   PHASE 4 STUB - always Suspicious, never executes
    linux_stub.rs  dev stub

extension/
  background.js    onDeterminingFilename redirect, session persistence,
                   health probe, notifications, fail-closed everywhere
  popup/           live scans, verdict history, structured findings
  native-messaging/com.aegis.sandbox.json   <- THE LIVE MANIFEST

scripts/
  install_native_host.ps1      all Chromium browsers, validates extension ID
  verify_native_host.ps1       walks the chain, names the broken link
  diagnose_native_messaging.ps1  captures browser-side native messaging logs
```

---

## 6. What remains — "the final nail"

Ordered by value **to the stated goal** (stop files that auto-execute), not by
the original spec order.

### 6.1 Archive inspection — HIGHEST VALUE, NOT YET STARTED

The largest remaining gap. A `.zip` containing `invoice.pdf.exe` currently
scores ~0: `structure.rs` deliberately does not flag executables inside
archives (a ZIP legitimately contains them), and the scanner never looks
*inside*. Most malware arrives this way.

Parse the ZIP central directory (no decompression needed for the listing) and
run the existing filename checks on each entry. Flag: executable entries,
double extensions inside, path traversal in entry names (zip-slip), and
compression ratios consistent with a zip bomb. `structure.rs` already locates
the EOCD record, so the hard part is done.

### 6.2 Authenticode signature check — HIGH VALUE, CHEAP

"Is this signed, and by whom" is the single strongest legitimacy signal, and
it is why Defender treats a Microsoft-signed binary differently from an unknown
one. `WinVerifyTrust` via the `windows` crate. A valid signature from a known
publisher should *reduce* risk; an invalid or absent one on an executable
should raise it slightly.

### 6.3 Auto-execution surface — DIRECTLY ON GOAL

The stated purpose is stopping files that execute on arrival. Enumerate what
actually achieves that on Windows and check for each: `.lnk` shortcuts with
embedded commands, Office macros (`vbaProject.bin` inside OOXML), `.scr`,
`.hta`, `.iso`/`.img` (mount-and-autorun), `autorun.inf`, and `.url`/`.website`
files. Several are just filename and container checks on top of 6.1.

### 6.4 Phase 4 — restricted-process sandbox

`CreateRestrictedToken` + Low integrity + Job Object (`KILL_ON_JOB_CLOSE`) +
separate desktop + no network + hard timeout. Design is in `DECISIONS.md`.

**Be honest about what this buys.** It shares the kernel; a kernel exploit
escapes it, and sandbox-aware malware behaves while watched. It is *corroborating
evidence for the ambiguous middle band*, not the main protection. The main
protection is Phases 2–3. Say so in `ARCHITECTURE.md`; do not let the popup
claim "verified safe" on a clean restricted detonation.

Execution stays gated: files already above `block_threshold` are blocked
statically and never run.

### 6.5 Phase 5 — ship quality

- `cargo audit` (never run — do this)
- `cargo fuzz` on `deep_forensic_scan` and the frame parser (spec §4 requires it)
- `ARCHITECTURE.md`: real diagram + an honest "how this differs from Defender"
- Popup polish; surface the health banner more prominently

### 6.6 Known smaller issues

- Chrome's extension rewriting can produce doubled names on release
  (`test_trojan.jpg` -> `test_trojan.jpg.jpeg`). Cosmetic.
- `scripts/test_memory.py`, `test_trojan_file.py`, `serve_test_downloads.py`
  still assume Linux paths; the IPC one was ported to Rust.
- `aegis/` (the old prototype) is dead code and should be deleted. It contains
  a `Command::spawn()` on downloaded files — a malware executor, not a sandbox.

---

## 7. How to work on this

```bash
cd aegis-host
cargo test                                   # 86 tests
cargo clippy --all-targets -- -D warnings
cargo build                                  # makes changes LIVE (see §4.2)
```

Then reload the extension at `edge://extensions` and download something.
Check `aegis-host/target/debug/aegis-host.log`.

**Standing rule for this project: run it, don't just read it.** Every real bug
here has been invisible to code review — log output corrupting the protocol
stream, a filename the browser silently rewrote, a registry hive for a browser
that was not installed. When you fix a silent failure, add a test that would
have caught it.

**Fail closed.** Ambiguity blocks. If Aegis cannot verify something, the file
does not get released — and the UI must say Aegis failed rather than implying
the file is dangerous (`isInfrastructureFailure` in `background.js`).

**Update `DECISIONS.md`** with every threshold and fail-open/fail-closed call.
