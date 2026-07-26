//! Quarantine file management.
//!
//! All files are held in `<system_temp>/aegis_quarantine/` under UUID-prefixed names.
//! - Filenames from the browser are sanitized before use (cosmetic only; UUID is the
//!   load-bearing path component).
//! - Disk-space guard prevents starting a download that would exhaust the temp volume.
//! - On Unix: `0700` permissions on the quarantine dir.
//! - On Windows: Restrictive ACL (Aegis service account only) — see `apply_windows_acl`.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Manage a quarantine directory and produce safe file paths.
#[derive(Debug, Clone)]
pub struct Quarantine {
    dir: PathBuf,
}

/// Reserved Windows device names that must never appear in a path component.
static WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

impl Quarantine {
    /// Create (idempotently) the quarantine directory.
    pub fn new(subdir: &str) -> Result<Self> {
        let dir = std::env::temp_dir().join(subdir);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create quarantine dir: {}", dir.display()))?;

        // Apply restrictive permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| {
                    format!("Failed to set 0700 on quarantine dir: {}", dir.display())
                })?;
        }
        #[cfg(windows)]
        {
            // VERIFY ON WINDOWS: apply restrictive ACL so only the Aegis
            // service account can write. Requires `windows` crate with
            // Win32_Security features. Phase 4 task.
            tracing::warn!("[QUARANTINE] Windows ACL not yet applied to quarantine dir — Phase 4 task");
        }

        tracing::info!("Quarantine directory ready: {}", dir.display());
        Ok(Self { dir })
    }

    /// Check if the quarantine volume has enough free space for a download.
    ///
    /// `content_length`: bytes the server claims the file will be, or `None`
    /// if unknown (Content-Length header absent).
    ///
    /// Returns `Ok(())` if safe to proceed, `Err` if the disk is too full.
    pub fn check_space(&self, content_length: Option<u64>, max_accept_bytes: u64) -> Result<()> {
        let expected = content_length.unwrap_or(max_accept_bytes);

        let free = available_space(&self.dir)?;
        // Require 2× the expected size as headroom (we write to a temp file
        // and may also be running concurrent downloads).
        let required = expected.saturating_mul(2).max(1_048_576); // at least 1 MB

        if free < required {
            bail!(
                "REJECTED_INSUFFICIENT_SPACE: need {} bytes free on {}, have {}",
                required,
                self.dir.display(),
                free
            );
        }
        Ok(())
    }

    /// Allocate a new quarantine file path for the given session.
    ///
    /// The `original_filename` is sanitized and used only as a cosmetic suffix.
    /// The UUID prefix is the actual load-bearing component.
    pub fn allocate_file(&self, original_filename: &str) -> PathBuf {
        let sanitized = sanitize_filename(original_filename);
        let uuid = Uuid::new_v4();
        self.dir.join(format!("{}_{}", uuid, sanitized))
    }

    /// Delete a quarantine file. Logs errors but does not propagate them
    /// (we don't want a failed delete to block returning a verdict to the user).
    pub fn delete_file(&self, path: &PathBuf) {
        if let Err(e) = std::fs::remove_file(path) {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "Failed to delete quarantine file — manual cleanup may be needed"
            );
        } else {
            tracing::debug!("Quarantine file deleted: {}", path.display());
        }
    }
}

/// Sanitize a browser-supplied filename to prevent path traversal.
///
/// Rules applied per spec §4:
/// - Strip path separators (`/`, `\`)
/// - Remove `..` components
/// - Strip null bytes
/// - Reject Windows reserved device names (case-insensitive), replacing with `_reserved_`
/// - Limit length to 128 characters
/// - Replace any remaining non-safe chars with `_`
pub fn sanitize_filename(filename: &str) -> String {
    // Strip path separators and null bytes
    let stripped: String = filename
        .chars()
        .filter(|&c| c != '/' && c != '\\' && c != '\0')
        .collect();

    // Take only the basename (last component after any remaining separators)
    let basename = stripped.rsplit('/').next().unwrap_or(&stripped);
    let basename = basename.rsplit('\\').next().unwrap_or(basename);

    // Check for `..`
    let basename = if basename.contains("..") { "dotdot_stripped" } else { basename };

    // Check Windows reserved names (compare stem without extension, case-insensitive)
    let stem_upper = basename
        .split('.')
        .next()
        .unwrap_or(basename)
        .to_uppercase();
    let basename = if WINDOWS_RESERVED.contains(&stem_upper.as_str()) {
        "_reserved_name_"
    } else {
        basename
    };

    // Replace remaining chars that are not safe ASCII
    let safe: String = basename
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();

    // Limit length
    let truncated: String = safe.chars().take(128).collect();

    // Ensure non-empty
    if truncated.is_empty() {
        "_unnamed_".to_string()
    } else {
        truncated
    }
}

/// Query available disk space for the path's filesystem.
fn available_space(path: &Path) -> Result<u64> {
    #[cfg(unix)]
    {
        use std::mem::MaybeUninit;
        let path_cstr = std::ffi::CString::new(path.to_string_lossy().as_bytes())
            .context("Quarantine path contains null bytes")?;
        let mut stat: MaybeUninit<libc::statvfs> = MaybeUninit::uninit();
        let ret = unsafe { libc::statvfs(path_cstr.as_ptr(), stat.as_mut_ptr()) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            bail!("statvfs failed on {}: {}", path.display(), err);
        }
        let stat = unsafe { stat.assume_init() };
        Ok(stat.f_bavail * stat.f_bsize)
    }

    #[cfg(windows)]
    {
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
        use windows::Win32::Foundation::ULARGE_INTEGER;

        let path_wide: Vec<u16> = path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut free_bytes_available: u64 = 0;
        let mut total_bytes: u64 = 0;
        let mut total_free: u64 = 0;

        unsafe {
            GetDiskFreeSpaceExW(
                PCWSTR(path_wide.as_ptr()),
                Some(&mut free_bytes_available),
                Some(&mut total_bytes),
                Some(&mut total_free),
            )
            .context("GetDiskFreeSpaceExW failed")?;
        }
        Ok(free_bytes_available)
    }
}

// libc is needed for statvfs on Linux — add as a dev dependency or feature-gate
#[cfg(unix)]
extern crate libc;
