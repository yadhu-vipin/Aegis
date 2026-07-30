//! Linux dev-mode sandbox stub.
//!
//! This is compiled on `#[cfg(unix)]` and implements the `Sandbox` trait
//! as a no-op that logs its intent and returns `Verdict::Suspicious` (fail
//! cautious, not fail open). This lets the full pipeline be exercised on the
//! Linux dev box without any Windows dependency.

use crate::sandbox::{DetonationReport, Sandbox, Verdict};
use anyhow::Result;
use async_trait::async_trait;
use std::path::Path;

/// Dev-mode sandbox stub — does NOT execute the binary.
#[derive(Debug, Default)]
pub struct StubSandbox;

impl StubSandbox {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Sandbox for StubSandbox {
    async fn detonate(&self, binary_path: &Path, timeout_secs: u64) -> Result<DetonationReport> {
        tracing::warn!(
            path = %binary_path.display(),
            timeout = timeout_secs,
            "[STUB] Would detonate here on Windows HCS — returning Suspicious (fail cautious). \
             Deploy on Windows to enable real sandbox execution."
        );

        // Fail cautious: report suspicious so the calling code treats this
        // as if the sandbox saw something it didn't like.
        Ok(DetonationReport {
            exit_code: None,
            flagged_behaviors: vec![
                "STUB: HCS not available on Linux dev machine — treat as suspicious".to_string(),
            ],
            network_attempts: vec![],
            verdict: Verdict::Suspicious,
        })
    }
}
