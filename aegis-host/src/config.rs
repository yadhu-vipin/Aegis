//! Configuration loader for aegis-host.
//!
//! Loads `aegis.toml` from the directory containing the binary (or the
//! current working directory as a fallback). Fails fast with a clear error
//! if the file is missing or malformed — never silently defaults.

#![allow(dead_code)]

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;
use std::time::Duration;

/// Top-level config, mirrors the structure of aegis.toml.
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub host: HostConfig,
    pub risk: RiskConfig,
    pub chunking: ChunkingConfig,
    pub quarantine: QuarantineConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HostConfig {
    pub log_level: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RiskConfig {
    pub sandbox_threshold: f32,
    pub block_threshold: f32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ChunkingConfig {
    pub chunk_size: usize,
    pub ring_buffer_chunks: usize,
    pub per_chunk_timeout_secs: u64,
    pub total_transfer_timeout_secs: u64,
    /// Hard ceiling on a single download, enforced continuously as chunks
    /// arrive. Without it, a download with no Content-Length can write past
    /// whatever the disk-space guard reserved.
    pub max_download_bytes: u64,
    /// Largest file the whole-file pass will load into memory.
    ///
    /// Structure, entropy and PE analysis need the complete file, so they are
    /// the one place memory is not flat. Larger files keep their streaming
    /// scan and skip these checks, and the verdict says so.
    #[serde(default = "default_max_whole_file_scan_bytes")]
    pub max_whole_file_scan_bytes: u64,
}

fn default_max_whole_file_scan_bytes() -> u64 {
    64 * 1024 * 1024
}

impl ChunkingConfig {
    pub fn per_chunk_timeout(&self) -> Duration {
        Duration::from_secs(self.per_chunk_timeout_secs)
    }
    pub fn total_transfer_timeout(&self) -> Duration {
        Duration::from_secs(self.total_transfer_timeout_secs)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct QuarantineConfig {
    pub subdir: String,
    pub keep_flagged_samples: bool,
}

impl Config {
    /// Load config from `aegis.toml` relative to the binary or cwd.
    /// Returns an error if the file cannot be found or parsed.
    pub fn load() -> Result<Self> {
        let path = Self::find_config_path()?;
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let config: Config = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn find_config_path() -> Result<PathBuf> {
        // Try next to the binary first
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                let candidate = dir.join("aegis.toml");
                if candidate.exists() {
                    return Ok(candidate);
                }
                // Try one level up (common when running from target/debug/)
                if let Some(parent) = dir.parent() {
                    let candidate = parent.join("aegis.toml");
                    if candidate.exists() {
                        return Ok(candidate);
                    }
                    // Try two levels up (target/debug/ → project root)
                    if let Some(grandparent) = parent.parent() {
                        let candidate = grandparent.join("aegis.toml");
                        if candidate.exists() {
                            return Ok(candidate);
                        }
                    }
                }
            }
        }
        // Fallback: cwd
        let cwd_candidate = std::env::current_dir()
            .context("Failed to get current directory")?
            .join("aegis.toml");
        if cwd_candidate.exists() {
            return Ok(cwd_candidate);
        }
        anyhow::bail!(
            "aegis.toml not found. Place it next to the aegis-host binary or in the working directory."
        )
    }

    fn validate(&self) -> Result<()> {
        if self.risk.sandbox_threshold <= 0.0 || self.risk.sandbox_threshold > 1.0 {
            anyhow::bail!(
                "risk.sandbox_threshold must be in (0.0, 1.0], got {}",
                self.risk.sandbox_threshold
            );
        }
        if self.risk.block_threshold <= 0.0 || self.risk.block_threshold > 1.0 {
            anyhow::bail!(
                "risk.block_threshold must be in (0.0, 1.0], got {}",
                self.risk.block_threshold
            );
        }
        if self.risk.sandbox_threshold >= self.risk.block_threshold {
            anyhow::bail!(
                "risk.sandbox_threshold ({}) must be < risk.block_threshold ({})",
                self.risk.sandbox_threshold,
                self.risk.block_threshold
            );
        }
        if self.chunking.chunk_size == 0 {
            anyhow::bail!("chunking.chunk_size must be > 0");
        }
        if self.chunking.ring_buffer_chunks == 0 {
            anyhow::bail!("chunking.ring_buffer_chunks must be > 0");
        }
        if self.chunking.max_download_bytes == 0 {
            anyhow::bail!("chunking.max_download_bytes must be > 0");
        }
        if self.chunking.max_download_bytes < self.chunking.chunk_size as u64 {
            anyhow::bail!(
                "chunking.max_download_bytes ({}) must be >= chunking.chunk_size ({}) — \
                 otherwise no download can ever complete",
                self.chunking.max_download_bytes,
                self.chunking.chunk_size
            );
        }
        Ok(())
    }
}
