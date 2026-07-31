//! Native Messaging IPC framing — Chrome's length-prefixed JSON protocol.
//!
//! Chrome native messaging spec:
//! - Every message from Chrome: [4-byte LE u32 length][JSON bytes]
//! - Every message to Chrome:   [4-byte LE u32 length][JSON bytes]
//! - Hard ceiling per message: 1MB in each direction (we enforce this).
//!
//! This module is the ONLY place that reads from stdin or writes to stdout.
//! All other code works with `serde_json::Value` or typed structs.

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::io::{self, Read, Write};

/// Maximum allowed message length (1 MB). Any frame claiming to be larger
/// is rejected as malformed — this prevents a malicious extension from
/// causing us to allocate arbitrarily large buffers.
pub const MAX_MESSAGE_BYTES: u32 = 1_048_576; // 1 MB

/// Read exactly one native-messaging frame from stdin.
///
/// Returns `Ok(None)` when stdin closes (Chrome disconnected cleanly).
/// Returns `Ok(Some(value))` on success.
/// Returns `Err` on malformed input (length > MAX_MESSAGE_BYTES, invalid JSON, IO error).
pub fn read_message() -> Result<Option<Value>> {
    let mut len_buf = [0u8; 4];
    match io::stdin().read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
            // Chrome closed the pipe — normal shutdown
            return Ok(None);
        }
        Err(e) => {
            return Err(e).context("Failed to read message length from stdin");
        }
    }

    let length = u32::from_le_bytes(len_buf);

    // Validate length BEFORE allocating — classic integer-overflow-into-OOM
    if length > MAX_MESSAGE_BYTES {
        bail!(
            "Incoming message length {} exceeds maximum allowed {} bytes — rejecting as malformed",
            length,
            MAX_MESSAGE_BYTES
        );
    }
    if length == 0 {
        bail!("Incoming message length is 0 — rejecting as malformed");
    }

    let mut json_buf = vec![0u8; length as usize];
    io::stdin()
        .read_exact(&mut json_buf)
        .context("Failed to read message body from stdin")?;

    let value: Value = serde_json::from_slice(&json_buf)
        .context("Failed to parse incoming message as JSON")?;

    Ok(Some(value))
}

/// Write one native-messaging frame to stdout.
///
/// The value is serialized to JSON, length-prefixed, and flushed atomically.
pub fn write_message(value: &Value) -> Result<()> {
    let json = serde_json::to_vec(value).context("Failed to serialize outgoing message")?;

    // Validate that our outgoing message also fits within the spec limit
    if json.len() > MAX_MESSAGE_BYTES as usize {
        bail!(
            "Outgoing message length {} exceeds maximum allowed {} bytes",
            json.len(),
            MAX_MESSAGE_BYTES
        );
    }

    let length = json.len() as u32;
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&length.to_le_bytes())
        .context("Failed to write message length to stdout")?;
    stdout
        .write_all(&json)
        .context("Failed to write message body to stdout")?;
    stdout.flush().context("Failed to flush stdout")?;
    Ok(())
}

/// Send a verdict response back to the Chrome extension.
pub fn send_verdict(status: &str, verdict: &str, session_id: Option<&str>) -> Result<()> {
    let mut obj = serde_json::json!({
        "type": "VERDICT",
        "status": status,
        "verdict": verdict,
    });
    if let Some(sid) = session_id {
        obj["session_id"] = Value::String(sid.to_string());
    }
    write_message(&obj)
}

/// Send a chunk acknowledgment back to the Chrome extension.
pub fn send_chunk_ack(session_id: &str, seq: u64) -> Result<()> {
    write_message(&serde_json::json!({
        "type": "CHUNK_ACK",
        "session_id": session_id,
        "seq": seq,
    }))
}

/// Tell the extension to cancel this download RIGHT NOW.
///
/// Sent mid-transfer when the running risk score crosses the block threshold.
/// This is the "catch it before it finishes downloading" path — the extension
/// responds with `chrome.downloads.cancel()`, so the remaining bytes are never
/// even fetched.
pub fn send_early_block(session_id: &str, risk_score: f32, reason: &str) -> Result<()> {
    write_message(&serde_json::json!({
        "type": "EARLY_BLOCK",
        "session_id": session_id,
        "risk_score": risk_score,
        "reason": reason,
    }))
}

/// Progress ping so the popup can show a live scanning state.
pub fn send_progress(session_id: &str, bytes_scanned: u64, risk_score: f32) -> Result<()> {
    write_message(&serde_json::json!({
        "type": "SCAN_PROGRESS",
        "session_id": session_id,
        "bytes_scanned": bytes_scanned,
        "risk_score": risk_score,
    }))
}

/// Terminal verdict for a watched download.
///
/// `released_path` is populated only when the file actually reached the user's
/// Downloads folder, so the extension never claims a release that did not occur.
pub fn send_final_verdict(
    session_id: &str,
    status: &str,
    verdict: &str,
    released_path: Option<&str>,
) -> Result<()> {
    // Concrete type needed: an empty slice gives the compiler nothing to infer
    // `T` from.
    let none: &[Value] = &[];
    send_final_verdict_with_findings(session_id, status, verdict, released_path, none)
}

/// Terminal verdict carrying structured findings.
///
/// The flat `verdict` string is kept for logging and for anything that cannot
/// render structure, but `findings` is what the UI should show: each carries a
/// plain-language title, the technical detail behind it, and why it matters.
/// A single pre-formatted string forces every surface to show all of it or
/// none, which is how "Aegis found something suspicious" ended up being the
/// only thing a user ever saw.
pub fn send_final_verdict_with_findings<T: serde::Serialize>(
    session_id: &str,
    status: &str,
    verdict: &str,
    released_path: Option<&str>,
    findings: &[T],
) -> Result<()> {
    let mut obj = serde_json::json!({
        "type": "VERDICT",
        "status": status,
        "verdict": verdict,
        "session_id": session_id,
    });
    if let Some(p) = released_path {
        obj["released_path"] = Value::String(p.to_string());
    }
    if !findings.is_empty() {
        obj["findings"] = serde_json::to_value(findings)
            .context("Failed to serialize findings for the verdict")?;
    }
    write_message(&obj)
}
