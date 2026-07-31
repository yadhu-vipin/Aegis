# Aegis — Handover

> **This file is descriptive, not aspirational.** Every claim here was verified
> by running the code.

**Read first:** [README.md](README.md) for what Aegis is and is not, then
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how it works, then
[DECISIONS.md](DECISIONS.md) for the audit trail of every threshold and
fail-open/fail-closed call. `AEGIS_BUILD_SPEC.md` is the original spec and is
**historical** — its architecture is not the one that exists; it carries a
banner saying so.

---

## 1. Current state

**Working end to end against real Microsoft Edge.**

```
376 tests passing
  131  unit
  108  fuzz (41,200 mutation cases per run)
  112  against containers written by real Windows tools
   12  IPC round-trip against the real binary
    9  end-to-end verdicts through the real binary
    4  sample-based

cargo clippy --all-targets -- -D warnings   clean
cargo audit                                 clean (92 crates)
```

### Complete

| Area | State |
|---|---|
| Interception, quarantine, release broker | done, verified in Edge |
| Streaming scan + early kill | done, verified in Edge |
| Magic bytes, intent (UTF-8 + UTF-16LE) | done |
| Structure, entropy, PE + import table | done |
| Archive inspection (ZIP central directory) | done |
| Auto-execution surface (LNK, macros, autorun) | done |
| Authenticode + catalog signing | done |
| Fuzzing, `cargo audit`, dependency reduction | done |
| Documentation | done |

### Deliberately not built

**Detonation / sandboxing.** Removed, not deferred. A user-mode sandbox shares
the kernel, tells you least about the samples that matter, and would require
running unknown malware on the user's own machine — to replace a safe
fail-closed default with a mechanism that can return "clean". Defender already
detonates unknown files in Microsoft's cloud. Full reasoning in DECISIONS.md
("Detonation dropped"); abandoned code on `wip/phase4-restricted-sandbox`.

**Layer 1 (URL/phishing ML).** A separate project. The host makes no network
requests at all.

### Not yet done

- **A download performed by an actual browser.** All six cases from §6 are now
  driven through the real host binary over the real protocol, with real files in
  the real quarantine directory (`tests/end_to_end.rs`). The one remaining gap
  is the browser itself calling `onDeterminingFilename` — which needs a human
  clicking a link, since the extension is loaded in the user's own Edge profile.
  Run `python scripts/serve_test_downloads.py` and work through §6.
- **No licence chosen.**
- **`install_native_host.sh`** (Linux) is untested against the current layout.

### A warning worth carrying forward

`notepad.exe` — signed by Microsoft, shipped with Windows — was **blocked at
risk 1.00** while 240 unit tests were green. Four defects compounded, all the
same mistake: treating an accumulation of weak evidence as strong evidence.
Full detail in DECISIONS.md ("Phase 7 — Calibration, found by running it").

The lesson is about test design. Every test asked *is malware detected?* and
none asked *is ordinary software delivered?* — and a scanner that blocks
everything passes the first kind perfectly. If you add a check, add a
false-positive test with it.

---

## 2. Things that WILL waste your time if you don't know them

These each cost hours. All verified.

1. **The browser is Microsoft Edge, not Chrome.** Chrome is not installed. Each
   Chromium browser reads native-host registrations only from its own registry
   hive. `scripts/install_native_host.ps1` handles all of them.

2. **The live host is `aegis-host/target/debug/aegis-host.exe`.** The manifest
   in play is `extension/native-messaging/com.aegis.sandbox.json`, which points
   directly at the build output — so `cargo build` makes changes live with no
   reinstall. **Its log is `aegis-host/target/debug/aegis-host.log`.** Reading
   the wrong log cost most of one session.

3. **Chromium rewrites the file extension.** You suggest `{uuid}.aegispart`;
   the browser re-applies its own extension from the MIME type, so a PDF lands
   as `{uuid}.pdf`. `validate_quarantine_path` therefore validates a **UUID
   stem**, never the extension. This also explains the doubled names in released
   files (`test_trojan.jpg` → `test_trojan.jpg.jpeg`) — that is the browser's
   own naming, faithfully reproduced, and not a bug.

4. **Windows 11 Home has no Hyper-V.** `vmcompute` does not exist. HCS was
   removed for this reason and should not come back.

5. **Defender wins the race on known malware.** It quarantines EICAR in the
   quarantine directory before we can read it (`os error 225`), handled as a
   normal BLOCK naming Defender. Do **not** add a Defender exclusion for that
   directory — it would disable real-time protection on the one folder
   guaranteed to contain live malware. **Do not use EICAR in on-disk tests**;
   you will measure Defender, not Aegis.

6. **PowerShell 5.1 reads BOM-less `.ps1` as ANSI.** A single em-dash in a
   string literal produces nine cascading parse errors pointing nowhere near the
   real problem. Keep `.ps1` files pure ASCII.

7. **PowerShell needs `$env:LOCALAPPDATA`, not `$LOCALAPPDATA`.** The bash form
   silently resolves to a wrong path.

8. **Execution policy blocks scripts.** Use
   `powershell -ExecutionPolicy Bypass -File .\scripts\<name>.ps1`.

9. **Quoted heredocs in this environment mangle escape sequences.** Writing Rust
   containing `\x89` through `cat <<'EOF'` produced UTF-8-encoded U+0089 and a
   file `grep` reported as binary. Use the editor tools for source files.

---

## 3. Key files

```
aegis-host/src/
  main.rs          message loop; handle_watch_session(); validate_quarantine_path()
  watcher.rs       tails the growing download, early-kill logic, bounded memory
  release.rs       the ONLY path into Downloads; collisions; stale sweep
  quarantine.rs    directory hardening (ACL / 0700), filename sanitisation
  risk/mod.rs      decide(): Release | Inconclusive | Block
  config.rs        aegis.toml; fails fast, never silently defaults
  ipc/native_messaging.rs   4-byte LE framing, 1 MB bound, read_frame(impl Read)
  scanner/
    mod.rs         deep_forensic_scan (per-span) + whole_file_scan_at + combine
    finding.rs     Finding { severity, title, detail, why } - the explanation layer
    magic_bytes.rs type vs extension
    intent.rs      red-flag strings, UTF-8 AND UTF-16LE at both alignments
    structure.rs   polyglots, trailing data, double extensions
    entropy.rs     Shannon entropy, packing/encryption
    pe.rs          sections, packers, entry point, import table
    archive.rs     ZIP central directory (+ZIP64); zip-slip, RLO, bombs
    autoexec.rs    LNK command lines, OOXML/OLE macros, autorun.inf, .url
    signature.rs   Authenticode + catalog; apply_trust_credit()

aegis-host/tests/
  ipc_roundtrip.rs    real binary over a real pipe: protocol and hostile frames
  end_to_end.rs       the six cases in section 6, driven through the real binary
  fuzz_parsers.rs     41,200 mutation cases; no panic AND no hang
  real_containers.rs  archives written by Compress-Archive, Explorer shortcuts
  scanner_samples.rs  the files in test_files/

extension/
  background.js    onDeterminingFilename redirect, session persistence,
                   health probe, notifications, fail-closed everywhere
  popup/           live scans, verdict history, structured findings
  native-messaging/com.aegis.sandbox.json   <- THE LIVE MANIFEST

scripts/
  install_native_host.ps1      all Chromium browsers, validates extension ID
  verify_native_host.ps1       walks the chain, names the broken link
  diagnose_native_messaging.ps1  captures browser-side logs
  serve_test_downloads.py      local file server for end-to-end testing
```

---

## 4. How to work on this

```bash
cd aegis-host
cargo test
cargo clippy --all-targets -- -D warnings
cargo build                                  # makes changes LIVE (see §2.2)
```

Then reload the extension at `edge://extensions` and download something. Check
`aegis-host/target/debug/aegis-host.log`.

For end-to-end testing:

```bash
python scripts/serve_test_downloads.py
```

**Standing rule: run it, don't just read it.** Every real bug here has been
invisible to code review — log output corrupting the protocol stream, a filename
the browser silently rewrote, a registry hive for a browser that was not
installed, quarantine hardening applied to a directory nothing used. When you
fix a silent failure, add a test that would have caught it.

**Fail closed.** Ambiguity holds the file. If Aegis cannot verify something, it
does not get released — and the UI must say Aegis failed rather than implying
the file is dangerous (`isInfrastructureFailure` in `background.js`).

**Watch the false-positive side.** Several tests assert that ordinary files are
*released*. A scanner that blocks everything is indistinguishable from a broken
one, and every new check is a fresh chance to start rejecting legitimate
downloads. If `ordinary_installer_archive_stays_below_the_sandbox_threshold` or
`ordinary_archive_is_still_released` ever fails, something has become a
false-positive generator.

**Update `DECISIONS.md`** with every threshold and fail-open/fail-closed call.

---

## 5. Suggested next steps

Ordered by value to the stated goal — stop files that auto-execute.

1. **Drive the six cases in §6 through a real browser.** Highest value, lowest
   effort, and the one form of verification this project has repeatedly shown to
   be irreplaceable.
2. **RAR and 7z listings.** `archive.rs` covers ZIP (and therefore OOXML, JAR,
   APK, and every Office document). RAR and 7z are the obvious gap, and both
   have parseable headers.
3. **MSI / OLE structured storage.** `autoexec.rs` detects legacy OLE macros by
   signature; walking the directory stream properly would also cover MSI custom
   actions, which execute on install.
4. **A licence.**

---

## 6. End-to-end checklist

| Sample | Expected |
|---|---|
| A benign PDF | RELEASE, reaches Downloads |
| A signed installer (e.g. from Microsoft) | RELEASE, publisher named in the popup |
| A ZIP containing `invoice.pdf.exe` | BLOCK, names the disguised entry |
| A password-protected ZIP | flagged unscannable, not silently cleared |
| A `.docm` with a macro | flagged, explains the auto-execution risk |
| An ordinary source-code ZIP | RELEASE — the false-positive check that matters most |

Do **not** use EICAR (see §2.5).
