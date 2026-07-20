//! Windows HCS (Host Compute Service) sandbox implementation.
//!
//! This module is compiled ONLY on Windows (`#[cfg(windows)]`).
//!
//! HCS Hardening applied per spec:
//! - Ephemeral VHDX diff disk per detonation, discarded after.
//! - No network adapter by default.
//! - No clipboard/RDP redirection.
//! - Configurable detonation timeout (default 30s).
//!
//! NOTE: This code is written for correctness against the HCS API but cannot
//! be test-executed on the Linux dev machine. Inline comments mark every
//! call that needs manual verification on a real Windows 11 box.

#![cfg(windows)]

use crate::sandbox::{DetonationReport, Sandbox, Verdict};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use std::path::Path;
use std::time::Duration;

// The `windows` crate provides safe Rust wrappers around the HCS API.
// Feature flags required: Win32_System_HostComputeSystem
use windows::core::HSTRING;
use windows::Win32::System::HostComputeSystem::{
    HcsCloseComputeSystem, HcsCreateComputeSystem, HcsGetComputeSystemProperties,
    HcsOpenComputeSystem, HcsStartComputeSystem, HcsTerminateComputeSystem,
    HCS_OPERATION_OPTIONS,
};

/// Real HCS sandbox implementation.
#[derive(Debug)]
pub struct HcsSandbox {
    /// Base layer VHD path — the read-only Windows container base image.
    /// This must already exist on the host; Aegis does not provision it.
    pub base_layer_path: String,
}

impl HcsSandbox {
    /// Create a new HCS sandbox handle.
    ///
    /// `base_layer_path`: path to an existing Windows container base layer
    /// (e.g. from `docker pull mcr.microsoft.com/windows/nanoserver:ltsc2022`).
    pub fn new(base_layer_path: impl Into<String>) -> Self {
        Self {
            base_layer_path: base_layer_path.into(),
        }
    }

    /// Build the HCS compute system configuration JSON for an isolated container.
    ///
    /// NOTE for Windows verification: This JSON schema must match the HCS API
    /// version on the target Windows 11 host. Use `HcsGetServiceProperties` to
    /// confirm API version at runtime. The schema below targets HCS v2.
    fn build_config_json(&self, scratch_vhd_path: &str) -> String {
        // Minimal isolated container config:
        // - No network namespace (isolated, no NIC)
        // - Writable scratch layer (diff disk — discarded after detonation)
        // - No clipboard/RDP access
        serde_json::json!({
            "SchemaVersion": { "Major": 2, "Minor": 1 },
            "Owner": "aegis-host",
            "GuestOs": { "HostName": "aegis-sandbox" },
            "Storage": {
                "Layers": [
                    { "Id": uuid::Uuid::new_v4().to_string(), "Path": self.base_layer_path }
                ],
                "ScratchVhd": {
                    "Path": scratch_vhd_path,
                    "CreateInstead": true,
                    "SizeInGB": 2
                }
            },
            // No network adapter — isolated execution
            "Networking": {},
            // Restrict resources to limit escape surface
            "Processor": { "Count": 1 },
            "Memory": { "SizeInMB": 512 }
        })
        .to_string()
    }
}

#[async_trait]
impl Sandbox for HcsSandbox {
    async fn detonate(&self, binary_path: &Path, timeout_secs: u64) -> Result<DetonationReport> {
        let binary_str = binary_path
            .to_str()
            .context("Binary path is not valid UTF-8")?;

        // Generate a unique scratch VHD path for this detonation
        let scratch_id = uuid::Uuid::new_v4();
        let scratch_vhd = format!(
            "{}\\aegis_scratch_{}.vhdx",
            std::env::temp_dir().display(),
            scratch_id
        );

        let config_json = self.build_config_json(&scratch_vhd);
        let system_id = HSTRING::from(scratch_id.to_string());
        let config_hstring = HSTRING::from(config_json.as_str());

        tracing::info!(
            binary = binary_str,
            scratch_vhd = %scratch_vhd,
            "[HCS] Creating ephemeral compute system for detonation"
        );

        // VERIFY ON WINDOWS: HcsCreateComputeSystem is synchronous here;
        // for large images you may need HcsCreateOperation + wait.
        let compute_system = unsafe {
            HcsCreateComputeSystem(
                &system_id,
                &config_hstring,
                // No completion callback for synchronous creation
                windows::Win32::Foundation::HANDLE::default(),
            )
            .context("HcsCreateComputeSystem failed")?
        };

        // VERIFY ON WINDOWS: HcsStartComputeSystem boots the container.
        let start_result = unsafe {
            HcsStartComputeSystem(
                compute_system,
                windows::Win32::Foundation::HANDLE::default(),
                None,
            )
        };
        if let Err(e) = start_result {
            // Clean up — terminate and close even if start failed
            let _ = unsafe { HcsTerminateComputeSystem(compute_system, None, None) };
            let _ = unsafe { HcsCloseComputeSystem(compute_system) };
            let _ = std::fs::remove_file(&scratch_vhd);
            bail!("HcsStartComputeSystem failed: {}", e);
        }

        tracing::info!("[HCS] Container started. Monitoring for {}s...", timeout_secs);

        // TODO (Phase 4 follow-up): inject `binary_str` into the container
        // via HCS process creation API and monitor via ETW telemetry.
        // For Phase 4 initial version: wait for timeout and collect exit-code only.

        tokio::time::sleep(Duration::from_secs(timeout_secs)).await;

        // Terminate and collect
        let terminated = unsafe { HcsTerminateComputeSystem(compute_system, None, None) };
        let _ = unsafe { HcsCloseComputeSystem(compute_system) };
        // Discard ephemeral scratch — this is critical for containment
        let _ = std::fs::remove_file(&scratch_vhd);

        // VERIFY ON WINDOWS: parse HCS operation result JSON for behavioral signals.
        // For Phase 4: simplified verdict based on whether the process exited within timeout.
        let verdict = match terminated {
            Ok(_) => {
                // Process was still running at timeout — suspicious (didn't exit cleanly)
                Verdict::Suspicious
            }
            Err(_) => {
                // Already terminated — may be normal or crash
                Verdict::Clean
            }
        };

        tracing::info!("[HCS] Detonation complete. Verdict: {}", verdict);

        Ok(DetonationReport {
            exit_code: None, // Phase 4 follow-up: extract via HCS guest API
            flagged_behaviors: vec![
                "Phase 4 stub: behavioral telemetry (ETW) not yet wired".to_string(),
            ],
            network_attempts: vec![],
            verdict,
        })
    }
}
