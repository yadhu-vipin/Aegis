//! Platform-agnostic sandbox trait and shared types.
//!
//! On Windows: `PlatformSandbox` = `RestrictedSandbox` (restricted token, Low
//! integrity, Job Object, isolated desktop — see `windows_restricted`).
//! On Unix/Linux: `PlatformSandbox` = `StubSandbox` (dev-mode no-op, logs intent).
//!
//! The HCS backend was removed: it requires the Host Compute Service, which is
//! unavailable on Windows Home (no `vmcompute` service, and Hyper-V /
//! Containers / VirtualMachinePlatform are all absent on that edition).

#![allow(dead_code)]

pub mod linux_stub;
#[cfg(windows)]
pub mod windows_restricted;

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
pub use windows_restricted::RestrictedSandbox as PlatformSandbox;
#[cfg(unix)]
pub use linux_stub::StubSandbox as PlatformSandbox;

/// Construct the sandbox backend for this platform.
///
/// Both backends are unit structs today, but callers must go through this
/// constructor rather than naming the type as a value — that is what broke the
/// Windows build previously (`let sandbox = PlatformSandbox;` only compiles
/// while every backend happens to be a unit struct).
pub fn platform_sandbox() -> PlatformSandbox {
    PlatformSandbox::new()
}
