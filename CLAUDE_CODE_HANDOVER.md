# Aegis — Claude Code Handover

> Drop this at your repo root as `CLAUDE_CODE_HANDOVER.md`. On your first session, tell Claude Code:
> `Read CLAUDE_CODE_HANDOVER.md and AEGIS_BUILD_SPEC.md fully before doing anything. Then run /context and tell me what's already loaded before we start.`

---

## 1. What This Project Is

**Aegis** is a two-layer, real-time endpoint download-safety system:

1. **Layer 1 (URL triage):** A Chrome extension that, on link hover, runs a lightweight ML model against the URL and shows an inline risk badge (safe/suspicious/phishing) before the user clicks.
2. **Layer 2 (file triage):** The same extension intercepts downloads via `chrome.downloads.onDeterminingFilename` (holds the file incomplete until scanned — not a race-prone `pause`/`cancel`), streams the bytes in fixed 256KB chunks to a local Rust native-messaging host, which runs magic-byte and heuristic scans. Files that are ambiguous or fail static checks get detonated inside a Windows HCS (Host Compute Service) micro-container before being released.

**Current state as of this handover:** the core pipeline (extension `background.js`, Rust host with native-messaging framing, chunked scanning, quarantine, risk decision, Linux stub sandbox) is written and has been compile-checked and smoke-tested end-to-end on Linux — EICAR correctly returns `BLOCKED`, a benign file returns `CLEARED`. The real Windows HCS sandbox implementation, the native-messaging host manifest/registration scripts, and the ML inference service for Layer 1 are **not yet built**.

**Goal:** take this from a working local pipeline to a portfolio-ready, production-grade demo — the kind of project that holds up under technical questioning in a generative-AI/AI-security interview. Correctness and defensibility of security claims matter more here than feature count.

**Two documents already exist and are authoritative — read both before making changes:**
- `AEGIS_BUILD_SPEC.md` — full architecture, directory structure, phased roadmap, chunking/memory-bounds requirements, secure-coding requirements.
- The `aegis-patch/` directory (or wherever you've merged it into the real tree) — the current working extension + host code, already fixing two real bugs found during testing (tracing logs corrupting the native-messaging stdout channel; `statvfs` called on a not-yet-existing path).

---

## 2. What To Build Next (priority order)

1. `com.aegis.sandbox.json` native messaging host manifest + Windows registry / macOS-Linux-dev registration scripts — without this, `connectNative()` fails and nothing else can be tested against a real browser.
2. `ml-service/` — the Python inference wrapper around the existing `.pt` model, with feature extraction reverse-engineered from `train.ipynb`/`newtrain.ipynb` (do not guess the preprocessing — read the notebooks first).
3. `sandbox/windows_hcs.rs` — real HCS detonation, per the hardening blueprint in `AEGIS_BUILD_SPEC.md` §4 of the original architecture doc.
4. `aegis.toml` config loading (currently hardcoded defaults in `risk::RiskThresholds::default()`).
5. Fuzz targets on `deep_forensic_scan` and the native-messaging frame parser — these two functions see 100% of untrusted input.

---

## 3. Skills & Plugins To Attach

Claude Code's **skills** are on-demand context — they only load into the conversation when invoked, unlike `CLAUDE.md` which loads every session. For a security-sensitive, multi-language project like this, moving specialized knowledge into skills instead of a bloated `CLAUDE.md` is both a cost optimization and a correctness one (Anthropic's own guidance: keep `CLAUDE.md` under ~200 lines and push workflow-specific detail into skills).

**Skills worth creating for this project** (put them under `.claude/skills/<name>/SKILL.md` in the repo so they're versioned with the code):

- **`aegis-chunking`** — encodes the memory-bounded streaming rules from the build spec (fixed 256KB chunks, bounded trailing-context ring buffer, disk-space guard before accepting a download). Point Claude at this any time it's touching `main.rs`'s chunk handling or `background.js`'s stream-forwarding loop, so it doesn't accidentally reintroduce full-file buffering.
- **`aegis-secure-coding`** — the hard rules from the build spec's secure-coding section (no `.unwrap()` on untrusted input, bounds-check every length field before allocation, filename sanitization rules, no shell-string interpolation). Invoke this before any PR-style review of new Rust code.
- **`aegis-hcs-schema`** — reference material for the HCS JSON schema fields, network isolation defaults, VHDX diff-disk handling. Keeps Claude from hallucinating HCS API details when it hasn't been given the real schema reference.
- **`native-messaging-protocol`** — the exact framing rules (4-byte LE length prefix, 1MB Chrome message ceiling, message type contract between extension and host). Small, load-bearing, worth its own skill since a subtle framing bug is what silently breaks the whole pipeline.

**Plugins to install from the official marketplace** (`/plugin marketplace` inside Claude Code, or `/plugin install`):

- **Code intelligence for Rust** — gives Claude precise go-to-definition/symbol navigation in `aegis-host/` instead of grep-based search, which matters once `sandbox/windows_hcs.rs` starts pulling in real WinAPI/HCS bindings with a lot of cross-references.
- **Automatic security review** (the built-in security-review plugin) — runs a model-backed check on each edit/commit. Genuinely useful here specifically because this codebase's entire job is handling untrusted input; a second pass catching things like an unchecked length field is worth the token cost.
- Consider a **JS/TS code intelligence plugin** too, since `background.js` is a real chunk of logic, not a throwaway script.

Check what's actually available and current with `/plugin marketplace list` and `/plugin install` inside a live session — the plugin catalog changes over time, so don't hardcode assumptions from this document.

---

## 4. Tracking Token Usage / Cost

- **`/usage`** — shows current-session token usage and (on Pro) a breakdown of what's consuming context: skills, subagents, plugins, individual MCP servers, each as a percentage. It also flags anything eating 10%+ of recent usage (e.g. long context, cache misses) with a specific tip. Session totals reset on `/clear`, not on ending the terminal — get in the habit of checking this before and after a big task.
- **`/context`** — shows what's actually loaded into the context window right now (CLAUDE.md, skills, MCP tool definitions, etc.). Run this early in a session to sanity-check nothing bloated is loading by default.
- **Status line** — you can configure the status line to show live context-window usage (`/statusline`) so you don't have to run `/usage` repeatedly.
- On a **Pro** plan specifically, dollar figures in `/usage` aren't the billing-relevant number (you have plan usage bars instead) — but the *token* breakdown is still the useful signal for spotting waste.

**Concrete habits for this project, given it spans Rust + JS + Python + a chunky spec file:**
- `/clear` between unrelated phases (e.g. finishing the HCS sandbox work before starting the ML service) — stale context from a different language/module wastes tokens on every subsequent message.
- Keep `CLAUDE_CODE_HANDOVER.md` and `AEGIS_BUILD_SPEC.md` as the loaded reference, but push the four skills above out of `CLAUDE.md` and into `.claude/skills/` so they're loaded only when relevant, not every session.
- Delegate anything verbose — running `cargo test`, reading a large notebook, parsing fuzz output — to a subagent so only the summary comes back into your main conversation. This project has at least one genuinely verbose operation already: reverse-engineering the `.pt` model's preprocessing from the notebooks is exactly the kind of exploration that should happen in a subagent, not inline.
- Use **plan mode** (Shift+Tab) before touching `sandbox/windows_hcs.rs` or anything HCS-schema-related — getting the isolation/network defaults wrong is expensive to unwind, and plan mode forces a reviewable proposal before code gets written.

---

## 5. Prompting Tips Specific to This Project

**Be specific, not exploratory, once a phase is scoped.** "Improve the scanner" triggers broad scanning of the whole `aegis-host/` tree. "Add a YARA-rule-based check to `scanner/intent.rs`, following the existing `IntentCheck` struct shape" gets a fast, targeted change. The build spec already breaks work into phases with explicit verify steps — reference the phase number directly: *"Do Phase 4 from AEGIS_BUILD_SPEC.md, HCS integration only, don't touch the extension."*

**Give Claude something to verify against.** This codebase already has a working pattern for this — the EICAR/benign smoke test used during earlier debugging. Ask Claude to write (and re-run) an equivalent test for anything new: *"After implementing the HCS stub-to-real swap, write a test that confirms the Linux stub path still returns Suspicious, not Clean, so a dev build never silently reports a file as safe."*

**State the security invariant, not just the feature.** Instead of "add disk space checking," say "add disk space checking — the invariant is that a download must never be allowed to exhaust the quarantine volume before a verdict is reached, and rejecting must fail closed, not open." Naming the invariant lets Claude catch edge cases you didn't think to enumerate (e.g., what happens if `Content-Length` lies).

**Use plan mode for anything touching the trust boundary.** The native-messaging stdin/stdout channel and the HCS schema are the two places where a subtle mistake has security consequences, not just correctness ones. Force a plan review there even if you'd skip it elsewhere.

**Correct Claude's assumptions about Windows-only code explicitly.** Since you develop on Linux but target Windows, be explicit every time: *"This needs to compile on Linux via the stub, but be written correctly for a real Windows target — don't guess at the HCS API shape, ask me to paste the actual `HCS_SYSTEM` schema docs if you're not certain."* Claude Code can't test the Windows path itself in your environment, so treat generated Windows-only code as a draft for your review, not verified-working — say this explicitly in the prompt so Claude flags uncertainty rather than presenting guesses with false confidence.

**Ask it to update `DECISIONS.md` as it goes** (already specified in the build spec's handoff prompt) — for a security tool, an audit trail of *why* a threshold or a design tradeoff was chosen is worth more than for a typical app, both for your own future reference and for explaining design choices in an interview.

**When something breaks silently (like the original EICAR pass-through), ask Claude to add a smoke test that would have caught it, not just fix the one instance.** The two real bugs found so far (log output corrupting the protocol stream, `statvfs` on a nonexistent path) were both the kind of thing that only surfaces by actually running the code — make "run it, don't just read it" a standing instruction for this project specifically, given how much of it is protocol-framing and filesystem-timing sensitive.
