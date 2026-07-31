# Aegis

**A download broker for Chromium browsers. Nothing reaches your Downloads
folder until it has been scanned and cleared.**

Aegis intercepts a download before it completes, redirects it into a quarantine
directory it controls, and analyses the bytes as the browser writes them. If the
file is dangerous the download is cancelled mid-transfer. If it is clean, and
only then, the file is moved into Downloads.

It is **additional protection alongside Windows Defender, not a replacement for
it.**

---

## The problem it addresses

The goal, in the project owner's words: *"not let files into the system which
start executing stuff as soon as it's downloaded."*

A conventional antivirus scans a file **after** it is written to disk. That is
the right design for what it does, but it means there is a window — however
brief — where a malicious file exists at the path the user expects, with the
name the user expects. Aegis removes that window by never putting the file
there in the first place.

---

## What Aegis is not

Being explicit about this matters more than the feature list, because a
security tool that overstates itself is worse than one that does less.

**Aegis is not an antivirus.** It has no signature database, no cloud lookup,
and no way to recognise a known malware family by name. Defender has all three
and they are better than anything this project could build.

**Aegis does not execute files.** There is no sandbox and no behavioural
analysis. Everything it knows, it learns by reading bytes. See
[Why there is no sandbox](#why-there-is-no-sandbox).

**Aegis does not protect against everything.** A file it clears is a file it
found nothing wrong with — not a file that is safe. Novel malware with no
structural tells will pass, and the honest description of what a clean verdict
means is "no evidence of the things Aegis knows how to look for".

**Aegis does not score URLs or detect phishing.** That was a separate layer in
the original design and is a separate project. This build makes no network
requests at all.

**Aegis is not a finished product.** It is a working system with real coverage
and a documented set of gaps.

---

## How this differs from Windows Defender

Defender is better at most of this. Two things it structurally cannot do are
where Aegis contributes.

### What Defender does better

| | |
|---|---|
| **Known malware** | A signature database and cloud reputation covering millions of samples. Aegis has none of this. |
| **Behavioural detection** | Watches processes as they run, at a level no user-mode tool can reach. |
| **Cloud detonation** | Block-at-First-Sight holds an unknown file while Microsoft's cloud actually runs it. |
| **Kernel visibility** | A filter driver sees every file operation on the machine. |

If Defender and Aegis disagree about a file, Defender is more likely to be
right. Aegis is designed to lose that race gracefully — when Defender
quarantines a sample from under it, that is reported as a block attributed to
Defender, not as an error.

### What Aegis adds

**1. Pre-completion interception.** Defender's on-write scanner acts once bytes
are on disk. Aegis reads them as they arrive and cancels the download
mid-flight, so a file identified at byte 4,096 of a 50 MB download never
finishes transferring.

**2. A hard quarantine boundary.** The file is never in your Downloads folder
at any point unless it passed. Not briefly, not pending a scan result. This is
a structural property rather than a matter of winning a race: the path the
browser writes to is inside a directory Aegis owns and locks down.

**3. Explanations rather than verdicts.** Defender tells you it blocked
`Trojan:Win32/Wacatac.B!ml`. Aegis tells you the archive contained a file
called `invoice.pdf.exe`, that Windows hides the `.exe` by default, and that
double-clicking it would run a program. Every finding carries what was
observed, and why it matters in terms of what could happen to you.

**4. Unknown samples.** For anything without a signature, Defender falls back
to heuristics and cloud reputation. Aegis's structural analysis — polyglots,
packers, import tables, archive contents — does not care whether a sample has
been seen before.

---

## What it detects

| Check | Looks for |
|---|---|
| **Magic bytes** | Real file type contradicting the extension — a program named `.jpg` |
| **Intent strings** | Malware-associated API names, scanned as UTF-8 *and* UTF-16LE |
| **Structure** | Polyglots, data appended after a format's logical end, double extensions |
| **Entropy** | Packing and encryption, interpreted relative to the declared type |
| **PE analysis** | Packer sections, W+X memory, entry point outside every section |
| **Import table** | What a program has *declared to Windows* that it will call |
| **Archives** | Contents of ZIPs without decompressing: disguised executables, zip-slip, encrypted entries, zip bombs |
| **Auto-execution** | `.lnk` command lines, Office macros, `autorun.inf`, `.hta`, `.iso`, `.scr` |
| **Authenticode** | Whether the file is signed, by whom, and whether the signature still matches the bytes |

The import table check deserves a note, because it is the strongest static
signal available. Searching a file for the text `CreateRemoteThread` proves
nothing — the string could be anywhere. Finding it in the **import table**
means the Windows loader has been instructed to resolve that function before
the program starts. It cannot be there by accident.

---

## Why there is no sandbox

An earlier design detonated suspicious files in an isolated process. That was
removed rather than finished, and the reasoning is worth stating because
"we have a sandbox" sounds like a straightforwardly good feature.

A user-mode sandbox on Windows Home shares the kernel with everything else on
the machine. It contains ordinary malware; it does not stop a kernel exploit,
and malware that checks whether it is being watched simply behaves for the
thirty seconds it is observed. So the evidence it produces is weak against
exactly the samples worth worrying about.

Against that: building it means **running unknown malware on your machine** to
obtain that weak evidence. Defender already detonates unknown files, in
Microsoft's cloud, on Microsoft's hardware.

The decisive argument is what it would replace. With no sandbox, an ambiguous
file is simply not delivered — a safe default. A sandbox introduces a mechanism
that can return "clean" and release a file that static analysis found
suspicious. Swapping a safe default for a weak signal is a bad trade.

Authenticode verification does the same job better: a binary signed by a real
publisher resolves out of the ambiguous band without anything being executed.

The abandoned implementation is preserved on the `wip/phase4-restricted-sandbox`
branch.

---

## Verdicts

| Verdict | Meaning | File delivered? |
|---|---|---|
| **Released** | Nothing of concern found | Yes |
| **Not cleared** | Signals found, below the threshold for a confirmed detection | No |
| **Blocked** | Confirmed detection | No |

The middle verdict is deliberately distinct. "We could not clear this" and
"this is malware" are different statements, and conflating them either cries
wolf or understates a real detection.

**Aegis fails closed.** If it cannot verify a file — the scanner crashed, the
host is unreachable, the analysis could not run — the file is not delivered.
When that happens the interface says *Aegis* failed, rather than implying the
file was dangerous.

---

## Requirements

- Windows 10/11 (Authenticode verification is Windows-only; the rest is portable)
- A Chromium browser: Chrome, Edge, Brave, or Vivaldi
- Rust 1.82+ to build (`std::iter::repeat_n`)

## Installing

```bash
cd aegis-host && cargo build --release
```

```bash
powershell -ExecutionPolicy Bypass -File .\scripts\install_native_host.ps1
```

Then load `extension/` as an unpacked extension at `edge://extensions` (or the
equivalent for your browser) with developer mode enabled.

`scripts/verify_native_host.ps1` walks the whole chain and names the broken link
if something does not work.

## Testing

```bash
cd aegis-host && cargo test
```

376 tests: 131 unit, 108 fuzz, 12 IPC round-trip, 112 against containers written
by real Windows tools, 9 end-to-end through the real binary, and 4 sample-based.

To regenerate the end-to-end fixtures and try it through a browser:

```bash
python scripts/make_test_files.py && python scripts/serve_test_downloads.py
```

**Half the end-to-end tests assert that ordinary files are RELEASED**, and that
half matters more. A scanner that blocks everything passes every detection test
ever written — and this one did exactly that: 240 unit tests were green while
Aegis blocked Microsoft-signed `notepad.exe` at maximum risk, because four
ordinary Windows API names were being summed. Four separate defects compounded,
all of them the same mistake of treating accumulated weak evidence as strong
evidence. `DECISIONS.md` documents each.

The fuzz suite runs 41,200 mutation cases against every parser on each
invocation, checking for panics *and* hangs. A crash in a security tool is an
availability failure: the host dying drops the native messaging port, which the
extension reads as "cannot verify", which cancels every subsequent download.

---

## Documentation

| | |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How it works — data flow, trust boundaries, module map |
| [DECISIONS.md](DECISIONS.md) | Every threshold and fail-open/fail-closed call, with reasoning |
| [HANDOVER.md](HANDOVER.md) | Current state, and what a future contributor needs to know |

## Licence

Not yet chosen.
