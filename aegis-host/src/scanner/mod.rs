//! Scanner orchestrator — `deep_forensic_scan()` as specified in the build spec.

#![allow(dead_code)]

pub mod magic_bytes;
pub mod intent;

use anyhow::Result;
use magic_bytes::MagicBytesResult;
use intent::IntentResult;

/// Combined result from a full forensic scan of one chunk.
#[derive(Debug, Default, Clone)]
pub struct ForensicResult {
    pub header_valid: bool,
    pub extension_mismatch: bool,
    pub dangerous_intent: bool,
    pub risk_score: f32,
    pub descriptions: Vec<String>,
}

/// Orchestrate static + intent scanning for one chunk.
///
/// Called for every chunk as it arrives. Magic-byte scanning only runs on
/// `is_first_chunk == true` (bytes 0..N of the file). Intent scanning runs
/// on every chunk with optional cross-boundary context from the ring buffer.
///
/// `context_prefix` — last few bytes of the previous chunk, used to catch
/// patterns that span a chunk boundary. Pass `None` for the first chunk.
pub async fn deep_forensic_scan(
    chunk: &[u8],
    filename: &str,
    is_first_chunk: bool,
    context_prefix: Option<&[u8]>,
) -> Result<ForensicResult> {
    let header_result: MagicBytesResult = if is_first_chunk {
        magic_bytes::scan_file(chunk, filename)?
    } else {
        MagicBytesResult::default()
    };

    let intent_result: IntentResult = intent::detect_dangerous_intent(chunk, context_prefix)?;

    let mut descriptions = Vec::new();
    if is_first_chunk && !header_result.description.is_empty() {
        descriptions.push(header_result.description.clone());
    }
    for flag in &intent_result.flags {
        descriptions.push(flag.clone());
    }

    // Risk combines magic-byte mismatch and intent signals.
    // Cap at 1.0 using saturating addition.
    let risk_score = (header_result.risk + intent_result.risk).min(1.0);

    Ok(ForensicResult {
        header_valid: header_result.valid,
        extension_mismatch: header_result.mismatch,
        dangerous_intent: intent_result.flagged,
        risk_score,
        descriptions,
    })
}
