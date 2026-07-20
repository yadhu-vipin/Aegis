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
