//! Platform-agnostic sandbox trait and shared types.
//!
//! On Windows: `PlatformSandbox` = `HcsSandbox` (real HCS detonation).
//! On Unix/Linux: `PlatformSandbox` = `StubSandbox` (dev-mode no-op, logs intent).

pub mod linux_stub;
#[cfg(windows)]
pub mod windows_hcs;

use anyhow::Result;
use async_trait::async_trait;
use std::path::Path;

/// Outcome of a sandbox detonation.
#[derive(Debug, Clone)]
pub struct DetonationReport {
    /// Process exit code, if the process exited within the timeout.
    pub exit_code: Option<i32>,
    /// List of flagged behaviors observed during detonation.
    pub flagged_behaviors: Vec<String>,
    /// Network connection attempts observed.
    pub network_attempts: Vec<String>,
    /// Final verdict.
    pub verdict: Verdict,
}

/// Verdict returned by the sandbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Clean => write!(f, "CLEAN"),
            Verdict::Suspicious => write!(f, "SUSPICIOUS"),
            Verdict::Malicious => write!(f, "MALICIOUS"),
        }
    }
}

/// The platform-agnostic sandbox interface.
#[async_trait]
pub trait Sandbox: Send + Sync {
    async fn detonate(&self, binary_path: &Path, timeout_secs: u64) -> Result<DetonationReport>;
}

// Platform selection at compile time.
#[cfg(windows)]
pub use windows_hcs::HcsSandbox as PlatformSandbox;
#[cfg(unix)]
pub use linux_stub::StubSandbox as PlatformSandbox;
