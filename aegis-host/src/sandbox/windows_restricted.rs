//! Windows restricted-process sandbox.
//!
//! Compiled only on Windows. Replaces the removed HCS backend, which required
//! Hyper-V / the Host Compute Service and therefore Windows Pro or better.
//! This machine class (Windows Home) has no `vmcompute` service at all, so HCS
//! was not a usable option.
//!
//! ## What this boundary is, and is not
//!
//! A restricted process shares the Windows kernel with everything else on the
//! machine. It contains commodity malware — the sample runs with a stripped
//! token at Low integrity, inside a Job Object that caps memory and process
//! count and kills the whole tree on close, on a separate desktop, with no
//! network and a CWD confined to a throwaway scratch directory.
//!
//! It does NOT stop a kernel exploit or a sandbox-escape chain, and malware
//! that fingerprints user-mode sandboxes can simply behave while watched. A VM
//! guarantees that escape requires a hypervisor bug; there is no equivalent
//! guarantee here. Never report a file as safe on the strength of a clean
//! restricted detonation alone — it is corroborating evidence, not proof.
//!
//! ## Status
//!
//! PHASE 1: fail-closed stub. Real isolation lands in Phase 4. Until then this
//! refuses to execute anything, exactly like `linux_stub`, so that a partially
//! built sandbox can never silently release a file.

use crate::sandbox::{DetonationReport, Sandbox, Verdict};
use anyhow::Result;
use async_trait::async_trait;
use std::path::Path;

/// Restricted-process detonation backend for Windows.
#[derive(Debug, Default)]
pub struct RestrictedSandbox;

impl RestrictedSandbox {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Sandbox for RestrictedSandbox {
    async fn detonate(&self, binary_path: &Path, timeout_secs: u64) -> Result<DetonationReport> {
        // PHASE 1 STUB — DO NOT MAKE THIS RETURN Clean.
        //
        // `risk::decide_after_sandbox()` maps Verdict::Clean -> Decision::Release.
        // Until the restricted token, Job Object, and desktop isolation in Phase 4
        // actually exist, we have observed nothing about this file, and "we
        // observed nothing" is not "this file is safe".
        tracing::warn!(
            path = %binary_path.display(),
            timeout = timeout_secs,
            "[RESTRICTED] Detonation not yet implemented (Phase 4) — returning Suspicious \
             (fail cautious). No sample was executed."
        );

        Ok(DetonationReport {
            exit_code: None,
            flagged_behaviors: vec![
                "STUB: restricted-process sandbox not yet implemented — sample was NOT \
                 executed. Verdict is a fail-closed default, not an observed behaviour."
                    .to_string(),
            ],
            network_attempts: vec![],
            verdict: Verdict::Suspicious,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A sandbox backend with no implemented isolation must never report Clean.
    /// If Phase 4 makes this test fail, that must be a deliberate change made
    /// alongside real isolation — not an accident.
    #[tokio::test]
    async fn stub_never_reports_clean() {
        let sandbox = RestrictedSandbox::new();
        let report = sandbox
            .detonate(Path::new("nonexistent.exe"), 1)
            .await
            .expect("stub detonation should not error");
        assert_ne!(
            report.verdict,
            Verdict::Clean,
            "an unimplemented sandbox must never report a sample as clean"
        );
    }
}
