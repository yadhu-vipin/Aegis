//! Release broker — the last gate before a file reaches the user.
//!
//! Chrome downloads into `<Downloads>/aegis-quarantine/{uuid}.aegispart`. That
//! directory is Aegis's; the user never browses it. Nothing arrives in the real
//! Downloads folder unless this module puts it there.
//!
//! Two outcomes, both terminal:
//!   * `release()` — move the quarantined file to Downloads under its original
//!     name, resolving collisions rather than clobbering.
//!   * `discard()`  — delete it.
//!
//! Both are best-effort about *reporting* but strict about ordering: we never
//! delete before we know the verdict, and we never move a file we have not
//! cleared.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

use crate::quarantine::sanitize_filename;

/// Result of a successful release.
#[derive(Debug)]
pub struct Released {
    /// Where the file actually landed (may differ from the requested name if a
    /// collision had to be resolved).
    pub final_path: PathBuf,
    /// True if the name was altered to avoid overwriting an existing file.
    pub renamed: bool,
}

/// Move a cleared file out of quarantine into the user's Downloads folder.
///
/// `downloads_dir` is the real Downloads root. `original_name` is the browser's
/// filename — it is sanitized before use, because it reaches us across the
/// extension trust boundary and is attacker-influenced.
pub fn release(
    quarantined: &Path,
    downloads_dir: &Path,
    original_name: &str,
) -> Result<Released> {
    if !quarantined.exists() {
        bail!(
            "cannot release {}: file is not in quarantine",
            quarantined.display()
        );
    }

    // Never trust the browser-supplied name as a path. Sanitizing strips
    // separators, `..`, null bytes, and Windows reserved device names.
    let safe_name = sanitize_filename(original_name);
    let (target, renamed) = resolve_collision(downloads_dir, &safe_name)?;

    // Try a plain rename first — same volume, atomic, cheap. Quarantine lives
    // under Downloads precisely so this is the normal case.
    match std::fs::rename(quarantined, &target) {
        Ok(()) => {}
        Err(_) => {
            // Cross-volume, or a transient lock. Fall back to copy + remove.
            std::fs::copy(quarantined, &target).with_context(|| {
                format!(
                    "copy {} -> {} during release",
                    quarantined.display(),
                    target.display()
                )
            })?;
            if let Err(e) = std::fs::remove_file(quarantined) {
                // The user has their file; a leftover quarantine copy is a
                // hygiene problem, not a safety one. Report, don't fail.
                tracing::warn!(
                    path = %quarantined.display(),
                    error = %e,
                    "released file copied but quarantine original could not be removed"
                );
            }
        }
    }

    tracing::info!(
        from = %quarantined.display(),
        to = %target.display(),
        renamed,
        "File released to Downloads"
    );

    Ok(Released {
        final_path: target,
        renamed,
    })
}

/// Delete a file that will not be released.
///
/// Errors are logged, not propagated: a failed delete must not stop the verdict
/// reaching the user. The file stays in quarantine, which is contained.
pub fn discard(quarantined: &Path, reason: &str) {
    match std::fs::remove_file(quarantined) {
        Ok(()) => tracing::info!(
            path = %quarantined.display(),
            reason,
            "Quarantined file discarded"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::debug!(path = %quarantined.display(), "already gone");
        }
        Err(e) => tracing::warn!(
            path = %quarantined.display(),
            error = %e,
            "Failed to delete quarantined file — it remains contained, but manual \
             cleanup may be needed"
        ),
    }
}

/// Pick a non-colliding path in `dir` for `name`.
///
/// Mirrors browser behaviour: `report.pdf`, `report (1).pdf`, `report (2).pdf`.
/// Never overwrites — silently replacing a user's existing file would be its
/// own kind of data loss.
fn resolve_collision(dir: &Path, name: &str) -> Result<(PathBuf, bool)> {
    let direct = dir.join(name);
    if !direct.exists() {
        return Ok((direct, false));
    }

    let path = Path::new(name);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("download");
    let ext = path.extension().and_then(|s| s.to_str());

    for n in 1..10_000u32 {
        let candidate = match ext {
            Some(e) => dir.join(format!("{stem} ({n}).{e}")),
            None => dir.join(format!("{stem} ({n})")),
        };
        if !candidate.exists() {
            return Ok((candidate, true));
        }
    }

    bail!("could not find a free filename for {name:?} in {}", dir.display())
}

/// Locate the user's Downloads directory.
#[cfg(windows)]
pub fn downloads_dir() -> Result<PathBuf> {
    // USERPROFILE\Downloads is correct unless the user has relocated the known
    // folder. Resolving the real KNOWNFOLDERID would need SHGetKnownFolderPath;
    // the extension also tells us the absolute path Chrome chose, so this is a
    // fallback rather than the primary source of truth.
    let profile = std::env::var("USERPROFILE")
        .context("USERPROFILE not set — cannot locate Downloads directory")?;
    Ok(PathBuf::from(profile).join("Downloads"))
}

#[cfg(unix)]
pub fn downloads_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME not set — cannot locate Downloads")?;
    Ok(PathBuf::from(home).join("Downloads"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_moves_file_and_keeps_name() {
        let q = tempfile::tempdir().unwrap();
        let d = tempfile::tempdir().unwrap();
        let src = q.path().join("uuid.aegispart");
        std::fs::write(&src, b"payload").unwrap();

        let out = release(&src, d.path(), "report.pdf").unwrap();
        assert_eq!(out.final_path, d.path().join("report.pdf"));
        assert!(!out.renamed);
        assert!(!src.exists(), "quarantine copy must not linger");
        assert_eq!(std::fs::read(&out.final_path).unwrap(), b"payload");
    }

    /// Releasing must never clobber a file the user already has.
    #[test]
    fn release_resolves_collisions_instead_of_overwriting() {
        let q = tempfile::tempdir().unwrap();
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("report.pdf"), b"ORIGINAL").unwrap();

        let src = q.path().join("uuid.aegispart");
        std::fs::write(&src, b"NEW").unwrap();

        let out = release(&src, d.path(), "report.pdf").unwrap();
        assert!(out.renamed);
        assert_eq!(out.final_path, d.path().join("report (1).pdf"));
        assert_eq!(
            std::fs::read(d.path().join("report.pdf")).unwrap(),
            b"ORIGINAL",
            "pre-existing file was overwritten"
        );
    }

    /// A malicious filename must not let a release escape the Downloads folder.
    #[test]
    fn release_cannot_escape_downloads_dir() {
        let q = tempfile::tempdir().unwrap();
        let d = tempfile::tempdir().unwrap();
        let src = q.path().join("uuid.aegispart");
        std::fs::write(&src, b"x").unwrap();

        let out = release(&src, d.path(), "../../../../evil.exe").unwrap();
        assert_eq!(
            out.final_path.parent().unwrap(),
            d.path(),
            "release escaped the target directory: {}",
            out.final_path.display()
        );
    }

    #[test]
    fn release_refuses_when_file_absent() {
        let d = tempfile::tempdir().unwrap();
        let missing = d.path().join("nope.aegispart");
        assert!(release(&missing, d.path(), "a.bin").is_err());
    }

    #[test]
    fn discard_removes_file_and_tolerates_missing() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("x.aegispart");
        std::fs::write(&f, b"bad").unwrap();
        discard(&f, "test");
        assert!(!f.exists());
        discard(&f, "test again"); // must not panic
    }
}
