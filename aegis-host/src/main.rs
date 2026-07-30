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
mod risk;
mod sandbox;
mod scanner;

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

#[tokio::main]
async fn main() {
    // Bootstrap logging to stderr (stdout is the native messaging channel)
    let subscriber = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("Failed to set tracing subscriber");

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
