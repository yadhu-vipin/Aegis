//! Aegis Host — Native Messaging entry point.
//!
//! Implements the Chrome native messaging protocol over stdin/stdout.
//! Reads length-prefixed JSON frames, processes download chunks, and writes
//! verdict frames back to the extension.
//!
//! Message flow:
//!   Extension → Host: START_DOWNLOAD {session_id, filename, content_length?}
//!   Extension → Host: CHUNK {session_id, seq, is_last, data: base64}
//!   Host → Extension: CHUNK_ACK {session_id, seq}         (backpressure)
//!   Host → Extension: VERDICT {session_id, status, verdict, descriptions}

mod config;
mod ipc;
mod quarantine;
mod release;
mod risk;
mod sandbox;
mod scanner;
mod watcher;

use anyhow::{Context, Result};
use base64::Engine as _;
use ipc::native_messaging;
use quarantine::Quarantine;
use risk::Decision;
use sandbox::{PlatformSandbox, Sandbox};
use scanner::ForensicResult;
use serde_json::Value;
use std::collections::VecDeque;
use tokio::io::AsyncWriteExt;
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

    let quarantine = Quarantine::new(&cfg.quarantine.subdir)?;
    let sandbox = sandbox::platform_sandbox();

    // Clear abandoned files from sessions that never reached a verdict.
    // The threshold is twice the total transfer timeout, so a legitimate
    // in-flight download in a concurrent session can never be swept.
    if let Ok(downloads) = release::downloads_dir() {
        release::sweep_stale(
            &downloads.join(&cfg.quarantine.subdir),
            cfg.chunking.total_transfer_timeout() * 2,
        );
    }

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
                if let Err(e) = handle_watch_session(&msg, &cfg, &sandbox).await {
                    tracing::error!(session = %sid, error = ?e, "watch session failed");
                    // Fail closed: no verdict means no release.
                    native_messaging::send_verdict(
                        "BLOCKED",
                        &format!("Not released: scanning failed ({e:#})"),
                        Some(&sid),
                    )?;
                }
            }
            "START_DOWNLOAD" => {
                handle_download_session(&msg, &cfg, &quarantine, &sandbox).await?;
            }
            "CHECK_URL" => {
                // Layer 1 — URL check forwarded to ML service
                handle_url_check(&msg, &cfg).await?;
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
async fn handle_watch_session(
    msg: &Value,
    cfg: &config::Config,
    sandbox: &PlatformSandbox,
) -> Result<()> {
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
    let downloads = release::downloads_dir()?;
    let quarantine_root = downloads.join(&cfg.quarantine.subdir);
    std::fs::create_dir_all(&quarantine_root).with_context(|| {
        format!("create download quarantine dir {}", quarantine_root.display())
    })?;

    let quarantine_path = match validate_quarantine_path(claimed_path, &quarantine_root) {
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
        watcher::WatchEvent::EarlyBlock { risk_score, reason } => {
            // Killed mid-flight. Tell the extension first so it cancels the
            // download promptly, then clean up both possible on-disk names.
            native_messaging::send_early_block(&session_id, risk_score, &reason)?;
            release::discard(&quarantine_path, "early block");
            let partial = format!("{}.crdownload", quarantine_path.display());
            release::discard(std::path::Path::new(&partial), "early block (partial)");

            native_messaging::send_final_verdict(
                &session_id,
                "BLOCKED",
                &format!("Blocked during download. {reason}"),
                None,
            )?;
        }

        watcher::WatchEvent::Completed(outcome) => {
            let aggregate = ForensicResult {
                risk_score: outcome.risk_score,
                ..Default::default()
            };
            let decision = risk::decide(&aggregate, &cfg.risk);

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
                    native_messaging::send_final_verdict(
                        &session_id,
                        "BLOCKED",
                        &format!(
                            "Blocked. Risk {:.2}. Signals: {}",
                            outcome.risk_score,
                            outcome.descriptions.join("; ")
                        ),
                        None,
                    )?;
                    false
                }

                Decision::Release => true,

                Decision::Sandbox | Decision::TooLargeToSandbox => {
                    if outcome.bytes_scanned > cfg.sandbox.max_detonation_size {
                        // Too big to detonate. FAIL CLOSED: we have an
                        // ambiguous file we cannot examine further.
                        release::discard(&quarantine_path, "too large to sandbox");
                        native_messaging::send_final_verdict(
                            &session_id,
                            "BLOCKED",
                            &format!(
                                "Not released: risk {:.2} needs sandbox analysis, but the file \
                                 ({} bytes) exceeds max_detonation_size ({}). Signals: {}",
                                outcome.risk_score,
                                outcome.bytes_scanned,
                                cfg.sandbox.max_detonation_size,
                                outcome.descriptions.join("; ")
                            ),
                            None,
                        )?;
                        false
                    } else {
                        match sandbox
                            .detonate(&quarantine_path, cfg.sandbox.detonation_timeout_secs)
                            .await
                        {
                            Ok(report) => {
                                let after = risk::decide_after_sandbox(&report.verdict);
                                if after == Decision::Release {
                                    true
                                } else {
                                    release::discard(&quarantine_path, "sandbox verdict");
                                    native_messaging::send_final_verdict(
                                        &session_id,
                                        "BLOCKED",
                                        &format!(
                                            "Sandbox verdict: {}. Behaviors: {}",
                                            report.verdict,
                                            report.flagged_behaviors.join("; ")
                                        ),
                                        None,
                                    )?;
                                    false
                                }
                            }
                            Err(e) => {
                                // FAIL CLOSED: a sandbox that errored told us
                                // nothing, which is not the same as "clean".
                                tracing::error!(error = ?e, "detonation failed");
                                release::discard(&quarantine_path, "detonation error");
                                native_messaging::send_final_verdict(
                                    &session_id,
                                    "BLOCKED",
                                    &format!("Not released: sandbox analysis failed ({e:#})"),
                                    None,
                                )?;
                                false
                            }
                        }
                    }
                }
            };

            if cleared {
                match release::release(&quarantine_path, &downloads, &original_filename) {
                    Ok(released) => {
                        native_messaging::send_final_verdict(
                            &session_id,
                            "COMPLETE",
                            &format!(
                                "Released to Downloads. Risk {:.2}{}",
                                outcome.risk_score,
                                if released.renamed {
                                    " (renamed to avoid overwriting an existing file)"
                                } else {
                                    ""
                                }
                            ),
                            Some(&released.final_path.to_string_lossy()),
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

/// Handle a full download session: read chunks → scan → decide → verdict.
async fn handle_download_session(
    start_msg: &Value,
    cfg: &config::Config,
    quarantine: &Quarantine,
    sandbox: &PlatformSandbox,
) -> Result<()> {
    // --- Parse START_DOWNLOAD message ---
    let session_id = start_msg
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let filename = start_msg
        .get("filename")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown_file")
        .to_string();

    let content_length: Option<u64> = start_msg
        .get("content_length")
        .and_then(|v| v.as_u64());

    tracing::info!(
        session = %session_id,
        filename = %filename,
        content_length = ?content_length,
        "Download session started"
    );

    // --- Disk-space guard ---
    if let Err(e) = quarantine.check_space(content_length, cfg.chunking.chunk_size as u64 * 100) {
        tracing::warn!("Disk space check failed: {}", e);
        native_messaging::send_verdict("REJECTED_INSUFFICIENT_SPACE", &e.to_string(), Some(&session_id))?;
        return Ok(());
    }

    // --- Quarantine file ---
    let quarantine_path = quarantine.allocate_file(&filename);
    let mut quarantine_file = tokio::fs::File::create(&quarantine_path)
        .await
        .with_context(|| format!("Failed to create quarantine file: {}", quarantine_path.display()))?;

    // --- Ring buffer for cross-chunk intent scanning ---
    let ring_cap = cfg.chunking.ring_buffer_chunks;
    let mut ring: VecDeque<Vec<u8>> = VecDeque::with_capacity(ring_cap);

    // --- Chunk processing state ---
    let mut chunk_scores: Vec<f32> = Vec::new();
    let mut cumulative_descriptions: Vec<String> = Vec::new();
    let mut is_first_chunk = true;
    let mut total_bytes: u64 = 0;
    // Next sequence number we will accept. Chunks must arrive in order,
    // starting at 0, with no gaps, duplicates, or replays.
    let mut expected_seq: u64 = 0;
    // Set ONLY on receipt of a chunk with is_last=true. Any other way out of
    // the loop means we did not see the whole file.
    let mut transfer_completed = false;

    // --- Chunk loop ---
    loop {
        let chunk_msg = match native_messaging::read_message()? {
            Some(m) => m,
            None => {
                // FAIL CLOSED: the pipe closed before is_last. We have a
                // truncated file. Previously this `break` fell through to the
                // verdict logic, which scored the partial bytes — and a
                // truncated file scores low, so it was RELEASED. That made
                // "send one benign chunk, then disconnect" a reliable way to
                // get an unscanned file cleared.
                tracing::warn!(
                    session = %session_id,
                    bytes_received = total_bytes,
                    chunks_received = expected_seq,
                    "Pipe closed mid-transfer — treating as incomplete, blocking"
                );
                break;
            }
        };

        let chunk_type = chunk_msg
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if chunk_type != "CHUNK" {
            tracing::warn!("Expected CHUNK, got '{}' in session {}", chunk_type, session_id);
            native_messaging::send_verdict(
                "REJECTED_MALFORMED",
                &format!("Expected CHUNK message, got '{}'", chunk_type),
                Some(&session_id),
            )?;
            quarantine.delete_file(&quarantine_path);
            return Ok(());
        }

        // Validate sequence number
        let seq = match chunk_msg.get("seq").and_then(|v| v.as_u64()) {
            Some(s) => s,
            None => {
                native_messaging::send_verdict(
                    "REJECTED_MALFORMED",
                    "CHUNK missing 'seq' field",
                    Some(&session_id),
                )?;
                quarantine.delete_file(&quarantine_path);
                return Ok(());
            }
        };

        // Enforce strict ordering. Previously `seq` was parsed and echoed back
        // in the ack but never checked, so out-of-order, duplicate, and
        // replayed chunks were all accepted and written in arrival order —
        // meaning an attacker controlled the byte layout of the quarantined
        // file relative to what the scanner saw. Spec §4 requires rejection.
        if seq != expected_seq {
            tracing::warn!(
                session = %session_id,
                expected = expected_seq,
                got = seq,
                "Out-of-order chunk sequence — rejecting session"
            );
            native_messaging::send_verdict(
                "REJECTED_MALFORMED",
                &format!("Out-of-order chunk: expected seq {expected_seq}, got {seq}"),
                Some(&session_id),
            )?;
            quarantine.delete_file(&quarantine_path);
            return Ok(());
        }
        expected_seq = expected_seq.saturating_add(1);

        let is_last = chunk_msg.get("is_last").and_then(|v| v.as_bool()).unwrap_or(false);

        // Decode base64 chunk data
        let data_b64 = match chunk_msg.get("data").and_then(|v| v.as_str()) {
            Some(d) => d,
            None => {
                native_messaging::send_verdict(
                    "REJECTED_MALFORMED",
                    "CHUNK missing 'data' field",
                    Some(&session_id),
                )?;
                quarantine.delete_file(&quarantine_path);
                return Ok(());
            }
        };

        let chunk_bytes = match base64::engine::general_purpose::STANDARD.decode(data_b64) {
            Ok(b) => b,
            Err(e) => {
                native_messaging::send_verdict(
                    "REJECTED_MALFORMED",
                    &format!("CHUNK data is not valid base64: {}", e),
                    Some(&session_id),
                )?;
                quarantine.delete_file(&quarantine_path);
                return Ok(());
            }
        };

        // Validate chunk size — reject absurdly large chunks
        if chunk_bytes.len() > cfg.chunking.chunk_size * 4 {
            native_messaging::send_verdict(
                "REJECTED_MALFORMED",
                &format!(
                    "Chunk size {} exceeds maximum allowed {}",
                    chunk_bytes.len(),
                    cfg.chunking.chunk_size * 4
                ),
                Some(&session_id),
            )?;
            quarantine.delete_file(&quarantine_path);
            return Ok(());
        }

        total_bytes = total_bytes.saturating_add(chunk_bytes.len() as u64);

        // Continuous size ceiling. The up-front disk-space guard reserves based
        // on Content-Length, or on a default when it is absent — but nothing
        // forced the actual transfer to stay within that reservation, so a
        // length-less download could write until the volume filled.
        if total_bytes > cfg.chunking.max_download_bytes {
            tracing::warn!(
                session = %session_id,
                total_bytes,
                limit = cfg.chunking.max_download_bytes,
                "Download exceeded max_download_bytes — rejecting"
            );
            native_messaging::send_verdict(
                "REJECTED_TOO_LARGE",
                &format!(
                    "Download exceeded maximum allowed size ({} bytes > {} limit)",
                    total_bytes, cfg.chunking.max_download_bytes
                ),
                Some(&session_id),
            )?;
            quarantine.delete_file(&quarantine_path);
            return Ok(());
        }

        // Build context prefix from tail of ring buffer
        let context_prefix: Option<Vec<u8>> = if ring.is_empty() {
            None
        } else {
            // Take the last 256 bytes from the most recent ring entry
            let last = ring.back().unwrap();
            Some(last.iter().rev().take(256).rev().cloned().collect())
        };

        // Scan this chunk
        let scan_result = scanner::deep_forensic_scan(
            &chunk_bytes,
            &filename,
            is_first_chunk,
            context_prefix.as_deref(),
        )
        .await?;

        chunk_scores.push(scan_result.risk_score);
        cumulative_descriptions.extend(scan_result.descriptions.clone());

        // Write chunk to quarantine
        quarantine_file
            .write_all(&chunk_bytes)
            .await
            .with_context(|| "Failed to write chunk to quarantine file")?;

        // Update ring buffer (bounded, oldest dropped)
        if ring.len() >= ring_cap {
            ring.pop_front();
        }
        ring.push_back(chunk_bytes);

        is_first_chunk = false;

        // Send backpressure ack before reading next chunk
        native_messaging::send_chunk_ack(&session_id, seq)?;

        if is_last {
            transfer_completed = true;
            break;
        }
    }

    // Flush quarantine file
    quarantine_file.flush().await?;
    drop(quarantine_file);

    // FAIL CLOSED on a truncated transfer. We never saw is_last, so we scanned
    // a prefix of the file and know nothing about the rest. A partial file
    // scores low precisely because the interesting bytes have not arrived.
    if !transfer_completed {
        quarantine.delete_file(&quarantine_path);
        native_messaging::send_verdict(
            "BLOCKED",
            &format!(
                "Transfer incomplete: connection closed after {} bytes across {} chunks \
                 without an end-of-stream marker. Not released — a partial file cannot be \
                 cleared.",
                total_bytes, expected_seq
            ),
            Some(&session_id),
        )?;
        return Ok(());
    }

    // --- Aggregate risk ---
    let aggregate_risk = risk::aggregate_risk(&chunk_scores);
    let aggregate_result = ForensicResult {
        risk_score: aggregate_risk,
        ..Default::default()
    };

    let decision = risk::decide(&aggregate_result, &cfg.risk);

    tracing::info!(
        session = %session_id,
        risk_score = aggregate_risk,
        decision = %decision,
        total_bytes,
        "Download scan complete"
    );

    // --- Act on decision ---
    match &decision {
        Decision::Block => {
            quarantine.delete_file(&quarantine_path);
            native_messaging::send_verdict(
                "BLOCKED",
                &format!("File blocked. Risk score: {:.2}. Signals: {}", aggregate_risk,
                    cumulative_descriptions.join("; ")),
                Some(&session_id),
            )?;
        }

        Decision::Sandbox => {
            // Check if file is too large to sandbox
            if total_bytes > cfg.sandbox.max_detonation_size {
                tracing::warn!(
                    "File ({} bytes) exceeds max_detonation_size ({} bytes) — skipping sandbox",
                    total_bytes, cfg.sandbox.max_detonation_size
                );
                quarantine.delete_file(&quarantine_path);
                native_messaging::send_verdict(
                    "WARNING_TOO_LARGE_TO_SANDBOX",
                    &format!(
                        "File too large to sandbox ({} bytes > {} limit). \
                         Static-only verdict: risk_score={:.2}. Proceed with caution.",
                        total_bytes, cfg.sandbox.max_detonation_size, aggregate_risk
                    ),
                    Some(&session_id),
                )?;
            } else {
                // Detonate in sandbox
                tracing::info!("Sending to sandbox: {}", quarantine_path.display());
                let detonation = sandbox
                    .detonate(&quarantine_path, cfg.sandbox.detonation_timeout_secs)
                    .await;

                match detonation {
                    Ok(report) => {
                        let final_decision = risk::decide_after_sandbox(&report.verdict);
                        if final_decision == Decision::Release {
                            native_messaging::send_verdict(
                                "COMPLETE",
                                &format!(
                                    "Sandbox verdict: {}. File analyzed and verified clean.",
                                    report.verdict
                                ),
                                Some(&session_id),
                            )?;
                            // Delete the quarantine copy. This path previously
                            // leaked it — the pre-sandbox Release path deletes,
                            // this one did not. Spec §4 requires deletion once a
                            // verdict is reached.
                            quarantine.delete_file(&quarantine_path);
                        } else {
                            quarantine.delete_file(&quarantine_path);
                            native_messaging::send_verdict(
                                "BLOCKED",
                                &format!(
                                    "Sandbox verdict: {}. Behaviors: {}",
                                    report.verdict,
                                    report.flagged_behaviors.join("; ")
                                ),
                                Some(&session_id),
                            )?;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Sandbox detonation failed: {:?}", e);
                        quarantine.delete_file(&quarantine_path);
                        native_messaging::send_verdict(
                            "ERROR",
                            &format!("Sandbox execution failed: {:#}", e),
                            Some(&session_id),
                        )?;
                    }
                }
            }
        }

        Decision::Release => {
            native_messaging::send_verdict(
                "COMPLETE",
                &format!("File verified clean. Risk score: {:.2}", aggregate_risk),
                Some(&session_id),
            )?;
            // Note: On a real release, we'd move from quarantine → Downloads here.
            // For now the extension handles the actual download after receiving COMPLETE.
            quarantine.delete_file(&quarantine_path);
        }

        Decision::TooLargeToSandbox => {
            // `decide()` does not currently return this variant (the size check
            // lives in the Sandbox branch above), but a panic here would take
            // down the host and stop protecting the user — spec §4 forbids
            // panics on any path. Fail closed instead.
            tracing::error!(
                session = %session_id,
                "decide() returned TooLargeToSandbox unexpectedly — blocking (fail closed)"
            );
            quarantine.delete_file(&quarantine_path);
            native_messaging::send_verdict(
                "BLOCKED",
                "Internal decision error — file not released (fail closed)",
                Some(&session_id),
            )?;
        }
    }

    Ok(())
}

/// Handle a CHECK_URL message — forward to ML inference service.
async fn handle_url_check(msg: &Value, cfg: &config::Config) -> Result<()> {
    let url = match msg.get("url").and_then(|v| v.as_str()) {
        Some(u) => u.to_string(),
        None => {
            native_messaging::send_verdict("REJECTED_MALFORMED", "CHECK_URL missing 'url'", None)?;
            return Ok(());
        }
    };

    // Validate URL length — cap before sending to ML service
    if url.len() > 2048 {
        native_messaging::write_message(&serde_json::json!({
            "type": "URL_SCORE",
            "score": 0.5,
            "label": "unscored",
            "reason": "URL too long to score"
        }))?;
        return Ok(());
    }

    let client = reqwest::Client::builder()
        .timeout(cfg.ml.timeout())
        .build()
        .context("Failed to build HTTP client")?;

    let response = client
        .post(&cfg.ml.service_url)
        .json(&serde_json::json!({ "url": url }))
        .send()
        .await;

    match response {
        Ok(resp) => {
            let body: Value = resp
                .json()
                .await
                .unwrap_or_else(|_| serde_json::json!({"score": 0.5, "label": "unscored"}));

            // Validate response schema before trusting it
            let score = body.get("score").and_then(|v| v.as_f64()).unwrap_or(0.5);
            let label = body
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("unscored")
                .to_string();

            // Clamp score to [0, 1]
            let score = score.clamp(0.0, 1.0);

            native_messaging::write_message(&serde_json::json!({
                "type": "URL_SCORE",
                "score": score,
                "label": label,
            }))?;
        }
        Err(e) => {
            tracing::warn!("ML service unreachable: {} — failing open with unscored", e);
            native_messaging::write_message(&serde_json::json!({
                "type": "URL_SCORE",
                "score": 0.5,
                "label": "unscored",
                "reason": "ML service unreachable"
            }))?;
        }
    }

    Ok(())
}
