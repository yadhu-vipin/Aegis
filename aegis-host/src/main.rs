//! Aegis Host — Native Messaging entry point.
//!
//! Implements the Chrome native messaging protocol over stdin/stdout: reads
//! length-prefixed JSON frames, watches downloads as the browser writes them,
//! and writes verdict frames back to the extension.
//!
//! Message flow:
//!   Extension → Host: PING                                  (liveness probe)
//!   Host → Extension: PONG {version, exe, quarantine_subdir}
//!
//!   Extension → Host: WATCH_BEGIN {session_id, quarantine_path,
//!                                  original_filename}
//!   Host → Extension: PROGRESS   {session_id, bytes, score}  (advisory)
//!   Host → Extension: EARLY_BLOCK{session_id, risk_score, reason}
//!   Host → Extension: VERDICT    {session_id, status, verdict, findings,
//!                                 released_path?}
//!
//!   Extension → Host: CHECK_URL {url}                        (Layer 1)
//!   Host → Extension: URL_SCORE {score, label}
//!
//! The browser performs the single fetch it was always going to perform, into
//! a quarantine directory Aegis owns, and this process tails the file as it
//! grows. Nothing reaches the user's Downloads folder unless `release::release`
//! puts it there after a clean verdict.

mod config;
mod ipc;
mod quarantine;
mod release;
mod risk;
mod scanner;
mod watcher;

use anyhow::{Context, Result};
use ipc::native_messaging;
use quarantine::Quarantine;
use risk::Decision;
use scanner::ForensicResult;
use serde_json::Value;
use tracing::Level;

/// Fan log output to both stderr and the log file.
struct MultiWriter<A: std::io::Write, B: std::io::Write>(A, B);

impl<A: std::io::Write, B: std::io::Write> std::io::Write for MultiWriter<A, B> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Best-effort on both; a failing log sink must never break scanning.
        let _ = self.0.write_all(buf);
        let _ = self.1.write_all(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        let _ = self.0.flush();
        let _ = self.1.flush();
        Ok(())
    }
}

/// Open the on-disk log, next to the binary.
///
/// When Chrome spawns a native messaging host it swallows the host's stderr,
/// so stderr-only logging leaves no way to diagnose anything that happens in
/// the real deployment — which is the only place most of this code runs.
/// Appending to a file next to the binary is the difference between "downloads
/// mysteriously fail" and an actual diagnosis.
fn open_log_file() -> Option<(std::fs::File, std::path::PathBuf)> {
    // Try next to the binary first, then the temp directory.
    //
    // The fallback is not paranoia: when Edge spawned this host it was
    // observed to run, return a verdict, and write NO log — meaning it could
    // not create a file beside its own executable, even though the same
    // binary can when launched from a shell. Whatever restricts that (token,
    // integrity level, container), %TEMP% is writable by anything that can
    // run at all. Without a log there is no way to see what the host did in
    // the only environment that matters.
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("aegis-host.log"));
        }
    }
    candidates.push(std::env::temp_dir().join("aegis-host.log"));

    for path in candidates {
        if let Ok(f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            return Some((f, path));
        }
    }
    None
}

#[tokio::main]
async fn main() {
    // NEVER stdout — that is the native messaging frame channel, and a single
    // stray byte there desynchronises the length prefix and breaks the protocol.
    let opened = open_log_file();
    let log_path = opened.as_ref().map(|(_, p)| p.clone());
    let log_file = opened.map(|(f, _)| f);
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(Level::DEBUG)
        .with_writer(move || -> Box<dyn std::io::Write> {
            match log_file.as_ref().and_then(|f| f.try_clone().ok()) {
                Some(f) => Box::new(MultiWriter(std::io::stderr(), f)),
                None => Box::new(std::io::stderr()),
            }
        })
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");

    // Record who we are and what we can see. When this host misbehaves it is
    // almost always because the environment differs from a shell launch, so
    // capture that difference up front rather than inferring it later.
    tracing::info!(
        pid = std::process::id(),
        exe = ?std::env::current_exe().ok(),
        cwd = ?std::env::current_dir().ok(),
        log = ?log_path,
        user = ?std::env::var("USERNAME").ok(),
        localappdata = ?std::env::var("LOCALAPPDATA").ok(),
        temp = ?std::env::var("TEMP").ok(),
        args = ?std::env::args().collect::<Vec<_>>(),
        "=== aegis-host starting ==="
    );

    if let Err(e) = run().await {
        tracing::error!("Fatal error: {:?}", e);
        // Send a clean error verdict before exiting so the extension isn't left hanging
        let _ = native_messaging::send_verdict("ERROR", &format!("{:#}", e), None);
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cfg = config::Config::load().context("Failed to load aegis.toml")?;
    tracing::info!("Aegis host started. Config loaded.");

    // Secure the directory that will hold live samples, and do it before
    // accepting any message. FAIL CLOSED: `?` here aborts start-up, because a
    // quarantine an attacker could write to makes every later verdict
    // meaningless — the bytes scanned would not have to be the bytes released.
    let downloads = release::downloads_dir()?;
    let quarantine = Quarantine::secure(&downloads.join(&cfg.quarantine.subdir))?;

    // Clear abandoned files from sessions that never reached a verdict.
    // The threshold is twice the total transfer timeout, so a legitimate
    // in-flight download in a concurrent session can never be swept.
    release::sweep_stale(
        quarantine.dir(),
        cfg.chunking.total_transfer_timeout() * 2,
    );

    // Main message loop — process one session per invocation (Chrome spawns
    // a new host process per port.connectNative() call).
    loop {
        let msg = match native_messaging::read_message()? {
            Some(m) => m,
            None => {
                tracing::info!("Chrome closed the pipe — exiting cleanly.");
                return Ok(());
            }
        };

        let msg_type = match msg.get("type").and_then(|v| v.as_str()) {
            Some(t) => t.to_string(),
            None => {
                tracing::warn!("Received message without 'type' field — ignoring");
                native_messaging::send_verdict(
                    "REJECTED_MALFORMED",
                    "Message missing 'type' field",
                    None,
                )?;
                continue;
            }
        };

        match msg_type.as_str() {
            // Liveness probe. The extension sends this on start-up so a broken
            // installation is visible in the popup as "Aegis cannot reach its
            // scanner" rather than silently turning into "every download is
            // blocked" the next time the user downloads something.
            "PING" => {
                tracing::info!("PING received — host is reachable");
                native_messaging::write_message(&serde_json::json!({
                    "type": "PONG",
                    "version": env!("CARGO_PKG_VERSION"),
                    "exe": std::env::current_exe()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                    "quarantine_subdir": cfg.quarantine.subdir,
                }))?;
            }
            "WATCH_BEGIN" => {
                // Contain failures to this one download. Propagating here would
                // end run(), exit the process, and drop the native port — which
                // the extension correctly reads as "cannot verify" and turns
                // into a cancelled download. One unlucky file must not take the
                // host down and block every subsequent download.
                let sid = msg
                    .get("session_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                if let Err(e) = handle_watch_session(&msg, &cfg).await {
                    tracing::error!(session = %sid, error = ?e, "watch session failed");
                    // Fail closed: no verdict means no release.
                    native_messaging::send_verdict(
                        "BLOCKED",
                        &format!("Not released: scanning failed ({e:#})"),
                        Some(&sid),
                    )?;
                }
            }
            // START_DOWNLOAD / CHUNK belonged to the Phase 1 protocol, where
            // the extension re-fetched the URL and streamed the bytes here.
            // Phase 2 removed it: that design fetched the URL twice, so the
            // bytes scanned were not the bytes delivered, and it broke every
            // POST, token and auth-gated download. The handler is gone, and
            // this branch exists so the removal is an explicit refusal rather
            // than a silent "unknown message type".
            "START_DOWNLOAD" | "CHUNK" => {
                tracing::warn!(
                    msg_type = %msg_type,
                    "refusing retired chunk-streaming protocol — the extension must use WATCH_BEGIN"
                );
                native_messaging::send_verdict(
                    "REJECTED_MALFORMED",
                    "The chunk-streaming protocol was removed in Phase 2. Nothing is scanned \
                     or released through it. Update the extension to send WATCH_BEGIN.",
                    msg.get("session_id").and_then(|v| v.as_str()),
                )?;
            }
            "CHECK_URL" => {
                // Layer 1 — URL check forwarded to ML service
                handle_url_check(&msg).await?;
            }
            _ => {
                tracing::warn!("Unknown message type: {}", msg_type);
                native_messaging::send_verdict(
                    "REJECTED_MALFORMED",
                    &format!("Unknown message type: {}", msg_type),
                    msg.get("session_id").and_then(|v| v.as_str()),
                )?;
            }
        }
    }
}

/// Validate a path supplied by the extension before we touch it.
///
/// TRUST BOUNDARY. `quarantine_path` crosses from the browser extension into a
/// process that will read the file, and on a clean verdict *move* it into the
/// user's Downloads folder. An unvalidated path here would be an arbitrary file
/// read and an arbitrary file move — a compromised or buggy extension could
/// name `C:\Windows\System32\config\SAM` and have Aegis helpfully relocate it.
///
/// Both sides are canonicalized before comparison so `..`, symlinks, junctions,
/// and 8.3 short names cannot be used to slip outside the quarantine root.
fn validate_quarantine_path(
    claimed: &str,
    expected_root: &std::path::Path,
) -> Result<std::path::PathBuf> {
    let claimed_path = std::path::Path::new(claimed);

    let root = expected_root.canonicalize().with_context(|| {
        format!(
            "quarantine root {} does not exist or cannot be resolved",
            expected_root.display()
        )
    })?;

    // The download may not exist yet (Chrome creates `.crdownload` first), so
    // canonicalize the PARENT, which must already exist, and re-attach the
    // filename. Canonicalizing a missing path would just fail.
    let parent = claimed_path
        .parent()
        .context("quarantine path has no parent directory")?
        .canonicalize()
        .with_context(|| {
            format!("quarantine path parent {claimed:?} does not exist or cannot be resolved")
        })?;

    if !parent.starts_with(&root) {
        anyhow::bail!(
            "REJECTED: extension supplied a path outside the quarantine root. \
             claimed={claimed:?} resolved_parent={} root={}",
            parent.display(),
            root.display()
        );
    }

    let file_name = claimed_path
        .file_name()
        .context("quarantine path has no filename component")?;
    let name_str = file_name.to_string_lossy();

    // Guard against being pointed at an unrelated pre-existing file in the
    // directory by requiring the stem to be a UUID we could have issued.
    //
    // Do NOT check the extension. The extension suggests `{uuid}.aegispart`,
    // but Chromium re-applies its own extension from the response MIME type,
    // so a PDF actually lands as `{uuid}.pdf`. Requiring `.aegispart` rejected
    // every real download — the host was running correctly and refusing its
    // own quarantine files:
    //
    //   Redirecting "notes.pdf" -> aegis_quarantine/4a635126-....aegispart
    //   REJECTED: quarantine filename "4a635126-....pdf" is not a .aegispart file
    //
    // The security property comes from the canonicalized root containment
    // above; the UUID stem is defence in depth, and unlike the extension it is
    // something we control end to end.
    let stem = name_str.split('.').next().unwrap_or("");

    // `conflictAction: "uniquify"` can append " (1)", " (2)" on collision.
    let stem = stem
        .rsplit_once(" (")
        .filter(|(_, tail)| tail.ends_with(')') && tail[..tail.len() - 1].chars().all(|c| c.is_ascii_digit()))
        .map(|(head, _)| head)
        .unwrap_or(stem);

    if uuid::Uuid::parse_str(stem).is_err() {
        anyhow::bail!(
            "REJECTED: quarantine filename {name_str:?} does not start with a UUID \
             issued by Aegis"
        );
    }

    Ok(parent.join(file_name))
}

/// Watch a download Chrome is writing into quarantine, scanning as it grows.
///
/// This is the Phase 2 path: Chrome performs the single fetch (so cookies,
/// sessions, POST bodies and one-time tokens all work) into a directory Aegis
/// owns, and we tail it. Nothing reaches the user's Downloads folder unless
/// `release::release` puts it there.
async fn handle_watch_session(msg: &Value, cfg: &config::Config) -> Result<()> {
    let session_id = match msg.get("session_id").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            native_messaging::send_verdict(
                "REJECTED_MALFORMED",
                "WATCH_BEGIN missing 'session_id'",
                None,
            )?;
            return Ok(());
        }
    };

    let claimed_path = match msg.get("quarantine_path").and_then(|v| v.as_str()) {
        Some(p) if !p.is_empty() => p,
        _ => {
            native_messaging::send_verdict(
                "REJECTED_MALFORMED",
                "WATCH_BEGIN missing 'quarantine_path'",
                Some(&session_id),
            )?;
            return Ok(());
        }
    };

    let original_filename = msg
        .get("original_filename")
        .and_then(|v| v.as_str())
        .unwrap_or("download.bin")
        .to_string();

    // The quarantine root is a subdirectory of the real Downloads folder,
    // because Chrome's onDeterminingFilename only accepts paths relative to it.
    //
    // Re-secured per session rather than trusting the start-up call: the
    // directory sits inside the user's Downloads folder, where anything can
    // delete it between sessions, and a recreated directory would inherit that
    // folder's permissions instead of ours. `secure` is idempotent and cheap.
    let downloads = release::downloads_dir()?;
    let quarantine_root = Quarantine::secure(&downloads.join(&cfg.quarantine.subdir))?;
    let quarantine_root = quarantine_root.dir();

    let quarantine_path = match validate_quarantine_path(claimed_path, quarantine_root) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(session = %session_id, error = %e, "quarantine path rejected");
            native_messaging::send_verdict(
                "REJECTED_MALFORMED",
                &format!("{e:#}"),
                Some(&session_id),
            )?;
            return Ok(());
        }
    };

    tracing::info!(
        session = %session_id,
        path = %quarantine_path.display(),
        original = %original_filename,
        "Watching download in quarantine"
    );

    let target = watcher::WatchTarget::new(&quarantine_path);
    let mut w = watcher::DownloadWatcher::new(target, original_filename.clone());

    let sid = session_id.clone();
    let event = watcher::watch_download(&mut w, cfg, |bytes, score| {
        // Progress is advisory; a failed send must not abort the scan.
        let _ = native_messaging::send_progress(&sid, bytes, score);
    })
    .await?;

    match event {
        watcher::WatchEvent::EarlyBlock {
            risk_score,
            reason,
            findings,
        } => {
            // Killed mid-flight. Tell the extension first so it cancels the
            // download promptly, then clean up both possible on-disk names.
            native_messaging::send_early_block(&session_id, risk_score, &reason)?;
            release::discard(&quarantine_path, "early block");
            let partial = format!("{}.crdownload", quarantine_path.display());
            release::discard(std::path::Path::new(&partial), "early block (partial)");

            // Carry the findings. An early block is the most common outcome -
            // it is the entire point of scanning while downloading - so this is
            // usually the only explanation the user ever sees.
            native_messaging::send_final_verdict_with_findings(
                &session_id,
                "BLOCKED",
                &format!("Blocked during download. {reason}"),
                None,
                &findings,
            )?;
        }

        watcher::WatchEvent::Completed(outcome) => {
            // Streaming findings so far. Carry the booleans through rather
            // than defaulting them: `decide()` reads only risk_score today,
            // but silently feeding it `false` for extension_mismatch would be
            // a trap the moment that changes.
            let mut aggregate = ForensicResult {
                risk_score: outcome.risk_score,
                extension_mismatch: outcome.extension_mismatch,
                dangerous_intent: outcome.dangerous_intent,
                header_valid: outcome.header_valid,
                descriptions: outcome.descriptions.clone(),
                ..Default::default()
            };

            // Whole-file pass: structure, entropy, PE. These cannot run on a
            // prefix - locating a format's logical end, measuring entropy over
            // the file, and walking a PE section table all need every byte.
            if outcome.bytes_scanned <= cfg.chunking.max_whole_file_scan_bytes {
                match std::fs::read(&quarantine_path) {
                    Ok(bytes) => {
                        // Pass the on-disk path too: Authenticode verification
                        // runs through a Windows signature provider that takes
                        // a file, not a buffer.
                        match scanner::whole_file_scan_at(
                            &bytes,
                            &original_filename,
                            Some(&quarantine_path),
                        ) {
                            Ok(whole) => {
                                if whole.risk_score > 0.0 {
                                    tracing::info!(
                                        session = %session_id,
                                        structural = whole.structural_anomaly,
                                        entropy = whole.entropy_anomaly,
                                        pe = whole.pe_anomaly,
                                        risk = whole.risk_score,
                                        "Whole-file analysis found anomalies"
                                    );
                                }
                                aggregate = scanner::combine(&aggregate, &whole);
                            }
                            // FAIL CLOSED on analysis failure would be too
                            // aggressive here - the streaming scan already
                            // succeeded and stands on its own - but the gap
                            // must be visible in the verdict, not silent.
                            Err(e) => {
                                tracing::error!(error = ?e, "whole-file analysis failed");
                                aggregate.descriptions.push(format!(
                                    "[warning] whole-file analysis could not run ({e:#}); \
                                     verdict is based on streaming checks alone"
                                ));
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = ?e, "could not read quarantined file for analysis");
                        aggregate.descriptions.push(format!(
                            "[warning] file could not be re-read for whole-file analysis \
                             ({e}); verdict is based on streaming checks alone"
                        ));
                    }
                }
            } else {
                tracing::warn!(
                    session = %session_id,
                    bytes = outcome.bytes_scanned,
                    limit = cfg.chunking.max_whole_file_scan_bytes,
                    "File too large for whole-file analysis - streaming scan only"
                );
                aggregate.descriptions.push(format!(
                    "[note] {} bytes exceeds the {} byte whole-file analysis limit; \
                     polyglot, entropy and PE checks were skipped",
                    outcome.bytes_scanned, cfg.chunking.max_whole_file_scan_bytes
                ));
            }

            let decision = risk::decide(&aggregate, &cfg.risk);
            let outcome = watcher::WatchOutcome {
                risk_score: aggregate.risk_score,
                descriptions: aggregate.descriptions.clone(),
                ..*outcome
            };

            tracing::info!(
                session = %session_id,
                risk_score = outcome.risk_score,
                decision = %decision,
                bytes = outcome.bytes_scanned,
                "Download scan complete"
            );

            let cleared = match decision {
                Decision::Block => {
                    release::discard(&quarantine_path, "static verdict: block");
                    native_messaging::send_final_verdict_with_findings(
                        &session_id,
                        "BLOCKED",
                        &format!(
                            "Blocked. Risk {:.2}. Signals: {}",
                            outcome.risk_score,
                            outcome.descriptions.join("; ")
                        ),
                        None,
                        &aggregate.findings,
                    )?;
                    false
                }

                Decision::Release => true,

                // The ambiguous band: enough signal to be concerning, not
                // enough to be conclusive.
                //
                // Aegis does not execute downloads, so there is no further
                // evidence to gather — this is where the analysis ends, and
                // the file is not released. FAIL CLOSED.
                //
                // The message must not imply the file is known-malicious. It
                // is not: it is unresolved, which is a different thing and the
                // user deserves to be told which one they are looking at.
                // Blocking while saying "we could not clear this" is honest;
                // blocking while saying "this is malware" is not.
                //
                // Historically this branch detonated the file in a sandbox and
                // reported `Sandbox verdict: SUSPICIOUS. Behaviors: STUB...`,
                // which described the scanner's own unfinished state rather
                // than anything about the file. See DECISIONS.md
                // ("Detonation dropped") for why that stage is gone rather
                // than merely unimplemented.
                Decision::Inconclusive => {
                    release::discard(&quarantine_path, "inconclusive: not cleared for release");
                    native_messaging::send_final_verdict_with_findings(
                        &session_id,
                        "BLOCKED",
                        &format!(
                            "Not released. Aegis found signals it could not clear, but this is \
                             not a confirmed detection — risk {:.2}, below the {:.2} threshold \
                             for one. Aegis does not run downloads to settle the question, so \
                             the file is held rather than delivered. Signals: {}",
                            outcome.risk_score,
                            cfg.risk.block_threshold,
                            outcome.descriptions.join("; ")
                        ),
                        None,
                        &aggregate.findings,
                    )?;
                    false
                }
            };

            if cleared {
                match release::release(&quarantine_path, &downloads, &original_filename) {
                    Ok(released) => {
                        // Carry the findings on the RELEASE path too, not just
                        // on blocks.
                        //
                        // A cleared file still has things worth saying about
                        // it: "Signed by Microsoft Corporation" is the entire
                        // user-visible payoff of Authenticode verification, and
                        // it only ever appears here — a signed file passes, so
                        // it never reaches a block path. Sending an empty
                        // findings list meant the one check that can produce
                        // good news could never deliver any.
                        //
                        // It also makes the low-severity notes visible: "this
                        // archive contains a program" is worth knowing before
                        // opening it, even though it is not worth blocking.
                        native_messaging::send_final_verdict_with_findings(
                            &session_id,
                            "COMPLETE",
                            &format!(
                                "Released to Downloads. Risk {:.2}.{}{}",
                                outcome.risk_score,
                                provenance_summary(&aggregate.signature_status),
                                if released.renamed {
                                    " Renamed to avoid overwriting an existing file."
                                } else {
                                    ""
                                }
                            ),
                            Some(&released.final_path.to_string_lossy()),
                            &aggregate.findings,
                        )?;
                    }
                    Err(e) => {
                        // Could not deliver it. Leave it quarantined rather
                        // than half-releasing, and say so.
                        tracing::error!(error = ?e, "release failed");
                        native_messaging::send_final_verdict(
                            &session_id,
                            "ERROR",
                            &format!("File passed scanning but could not be released: {e:#}"),
                            None,
                        )?;
                    }
                }
            }
        }
    }

    Ok(())
}


/// One clause naming who signed a released file, if anyone.
///
/// Provenance is the only *positive* thing Aegis can report, and it belongs in
/// the released-file message where the user is deciding whether to open
/// something. Silence is deliberate for the unsignable majority: saying "this
/// PNG is unsigned" would be noise, because images are never signed and the
/// observation carries no information.
fn provenance_summary(status: &Option<scanner::signature::TrustStatus>) -> String {
    use scanner::signature::TrustStatus;
    match status {
        Some(TrustStatus::Trusted { publisher }) => match publisher {
            Some(p) => format!(" Signed by {p}."),
            None => " Carries a valid signature.".to_string(),
        },
        Some(TrustStatus::TrustedByCatalog { .. }) => {
            " Verified against a signed Windows catalogue.".to_string()
        }
        // An unsigned executable is worth mentioning on release precisely
        // because it passed: the user is about to run something whose origin
        // nobody can vouch for, and that is a fact about the file rather than
        // an accusation against it.
        Some(TrustStatus::Unsigned) => " Not digitally signed — its origin cannot be verified.".to_string(),
        Some(TrustStatus::Unavailable(_)) | None => String::new(),
        // The remaining states carry real risk, so they raise the score and
        // appear as findings. Restating them here would double-report.
        Some(_) => String::new(),
    }
}

/// Handle a CHECK_URL message.
///
/// Answers `unscored` and makes no network request. The protocol contract is
/// unchanged — the extension already treats `unscored` as "no opinion" and
/// shows a neutral badge — so this is behaviourally identical to the previous
/// implementation on this machine, where no scoring service has ever run.
///
/// **Why the HTTP client is gone.** This handler was the only code in the host
/// that could open a network connection, and it existed to reach a phishing-URL
/// model that is out of scope for Aegis (a separate project) and whose trained
/// weights are not in this repository. Carrying `reqwest` for it cost 126 of
/// the crate's 290 dependency edges, including one already flagged unmaintained
/// by `cargo audit` (RUSTSEC-2025-0134, `rustls-pemfile`).
///
/// A file scanner with no outbound network path is a materially better thing
/// to have on a machine than one with an HTTP stack it does not use: there is
/// no connection for a compromised host process to make, and no TLS stack in
/// the dependency tree to inherit advisories from. Restoring the call is a
/// dozen lines if Layer 1 is ever built — see DECISIONS.md.
///
/// Layer 1 fails OPEN, deliberately and unlike everything else here: a hover
/// badge is advisory, and browsing must not break because a scorer is absent.
/// The file pipeline fails closed. That asymmetry is intentional.
async fn handle_url_check(msg: &Value) -> Result<()> {
    if msg.get("url").and_then(|v| v.as_str()).is_none() {
        native_messaging::send_verdict("REJECTED_MALFORMED", "CHECK_URL missing 'url'", None)?;
        return Ok(());
    }

    native_messaging::write_message(&serde_json::json!({
        "type": "URL_SCORE",
        "score": 0.5,
        "label": "unscored",
        "reason": "URL scoring is not part of this build",
    }))?;

    Ok(())
}
