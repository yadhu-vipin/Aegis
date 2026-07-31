//! Quarantine directory hardening.
//!
//! The quarantine directory holds live, unscanned, potentially malicious files
//! for the whole time they are being examined. This module makes it as hostile
//! a place to tamper with as the platform allows:
//!
//! - On Unix: `0700`.
//! - On Windows: inheritance stripped, full control granted to exactly one
//!   principal — see [`apply_windows_acl`].
//!
//! **Which directory this is matters, and it moved.** Phase 1 held samples in
//! `<system_temp>/aegis_quarantine/`, so that is what this module used to
//! secure. Phase 2 moved them to `<Downloads>/aegis_quarantine/`, because
//! Chrome's `onDeterminingFilename` only accepts paths relative to the default
//! download directory — but the hardening was left pointing at the temp path.
//! The result was a directory that was carefully locked down and never used,
//! next to one that held every live sample and inherited whatever permissions
//! the user's Downloads folder happened to carry.
//!
//! [`Quarantine::secure`] therefore takes the path explicitly rather than
//! deriving it. There is now one way to name that directory and one place that
//! locks it.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

/// A quarantine directory that exists and has been locked down.
///
/// Holding one of these is evidence the directory was secured: it cannot be
/// constructed without [`Quarantine::secure`] succeeding.
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
    /// Create the quarantine directory if needed, then lock it down.
    ///
    /// Idempotent: safe to call on every host start-up and on every session.
    ///
    /// FAIL CLOSED — the caller must propagate an error from this rather than
    /// carrying on. A directory of untrusted samples that could not be secured
    /// is one where an attacker may be able to swap a file between the scan and
    /// the verdict, which turns a clean result into a lie.
    pub fn secure(dir: &Path) -> Result<Self> {
        let dir = dir.to_path_buf();
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
        apply_windows_acl(&dir)?;

        tracing::info!("Quarantine directory secured: {}", dir.display());
        Ok(Self { dir })
    }

    /// The secured directory.
    pub fn dir(&self) -> &Path {
        &self.dir
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
    // Take the basename FIRST, while separators are still present — stripping
    // them first (as this previously did) made the rsplit calls dead code.
    let basename = filename
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(filename);

    // Now drop separators (none should remain) and null bytes.
    let stripped: String = basename
        .chars()
        .filter(|&c| c != '/' && c != '\\' && c != '\0')
        .collect();

    // Collapse `..` rather than discarding the whole name. Path traversal is
    // already impossible here (the UUID prefix is the load-bearing component
    // and this result is only ever a suffix), so there is no reason to throw
    // away a legitimate name like `archive..v2.zip`.
    let basename = stripped.replace("..", "_");

    // Check Windows reserved names (compare stem without extension, case-insensitive)
    let stem_upper = basename
        .split('.')
        .next()
        .unwrap_or(&basename)
        .to_uppercase();
    let basename: &str = if WINDOWS_RESERVED.contains(&stem_upper.as_str()) {
        "_reserved_name_"
    } else {
        &basename
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

/// Lock the quarantine directory down to the current user only.
///
/// Strips inherited ACEs and grants full control to exactly one principal. The
/// directory holds live, unscanned, potentially malicious samples, so no other
/// local account should be able to read or swap them mid-scan.
///
/// Uses `icacls` rather than raw `SetNamedSecurityInfo` FFI: it is a documented
/// system tool, and building a DACL by hand is easy to get subtly and silently
/// wrong. Arguments are passed as an argument array — never an interpolated
/// shell string — per the secure-coding rules in the build spec §4.
///
/// FAIL CLOSED: an error here aborts host startup. If the directory that holds
/// untrusted samples cannot be secured, running anyway would mean scanning
/// files an attacker might be able to replace underneath us.
#[cfg(windows)]
fn apply_windows_acl(dir: &Path) -> Result<()> {
    use std::process::Command;

    let username = std::env::var("USERNAME")
        .context("USERNAME not set — cannot determine principal for quarantine ACL")?;
    let domain = std::env::var("USERDOMAIN").unwrap_or_else(|_| ".".to_string());
    let principal = format!("{domain}\\{username}");

    // 1. Remove all inherited ACEs so the parent temp dir's grants do not apply.
    let out = Command::new("icacls")
        .arg(dir)
        .arg("/inheritance:r")
        .output()
        .context("Failed to run icacls to strip inherited ACEs")?;
    if !out.status.success() {
        bail!(
            "icacls /inheritance:r failed on {}: {}",
            dir.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    // 2. Grant full control to the current user only.
    //    (OI) object inherit, (CI) container inherit, F full control.
    //    /grant:r replaces rather than adds to any existing grant.
    let out = Command::new("icacls")
        .arg(dir)
        .arg("/grant:r")
        .arg(format!("{principal}:(OI)(CI)F"))
        .output()
        .context("Failed to run icacls to grant quarantine access")?;
    if !out.status.success() {
        bail!(
            "icacls /grant:r failed on {} for {}: {}",
            dir.display(),
            principal,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    tracing::info!(
        dir = %dir.display(),
        principal = %principal,
        "Quarantine ACL applied — inheritance stripped, single-principal full control"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Path traversal must never survive sanitization. The UUID prefix is the
    /// load-bearing safety property, but the suffix must not be able to climb
    /// out of the quarantine directory on its own either.
    #[test]
    fn sanitize_strips_traversal() {
        for evil in [
            "../../../../Windows/System32/evil.exe",
            "..\\..\\Windows\\System32\\evil.exe",
            "/etc/passwd",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
        ] {
            let s = sanitize_filename(evil);
            assert!(!s.contains('/'), "slash survived in {s:?} (from {evil:?})");
            assert!(!s.contains('\\'), "backslash survived in {s:?} (from {evil:?})");
            assert!(!s.contains(".."), "dotdot survived in {s:?} (from {evil:?})");
        }
    }

    /// The basename must be taken BEFORE separators are filtered out.
    /// Filtering first turns "a/b/evil.exe" into "abevil.exe" — it leaks the
    /// directory components into the filename instead of discarding them.
    #[test]
    fn sanitize_takes_basename_not_concatenation() {
        assert_eq!(sanitize_filename("dir/sub/report.pdf"), "report.pdf");
        assert_eq!(sanitize_filename("dir\\sub\\report.pdf"), "report.pdf");
    }

    /// Legitimate names containing ".." should survive in recognisable form
    /// rather than being replaced wholesale.
    #[test]
    fn sanitize_preserves_legitimate_names() {
        assert_eq!(sanitize_filename("quarterly-report.pdf"), "quarterly-report.pdf");
        assert_eq!(sanitize_filename("archive..v2.zip"), "archive_v2.zip");
    }

    /// Windows reserved device names must not be usable as a path component.
    #[test]
    fn sanitize_rejects_reserved_device_names() {
        for reserved in ["CON", "con.txt", "NUL.dat", "COM1.bin", "lpt9.exe"] {
            assert_eq!(
                sanitize_filename(reserved),
                "_reserved_name_",
                "reserved device name {reserved:?} was not neutralised"
            );
        }
    }

    #[test]
    fn sanitize_strips_null_bytes_and_never_returns_empty() {
        assert!(!sanitize_filename("evil\0.exe").contains('\0'));
        assert!(!sanitize_filename("").is_empty());
        assert!(!sanitize_filename("///").is_empty());
    }

    #[test]
    fn sanitize_bounds_length() {
        let long = "a".repeat(5000);
        assert!(sanitize_filename(&long).chars().count() <= 128);
    }
}

// libc is needed for statvfs on Linux — add as a dev dependency or feature-gate
#[cfg(unix)]
extern crate libc;
