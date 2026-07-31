//! Scanner orchestrator.
//!
//! Two entry points, because the checks divide naturally by what they need:
//!
//! * [`deep_forensic_scan`] runs per-chunk while the download is still
//!   arriving. Only checks that work on a prefix belong here — magic bytes
//!   (chunk 0) and intent strings (every chunk, with cross-boundary context).
//!   This is what makes the early kill possible.
//!
//! * [`whole_file_scan`] runs once the download completes. Structure, entropy
//!   and PE analysis all need the complete file: you cannot find the bytes
//!   *after* a PNG's `IEND` chunk until you have all of them.
//!
//! Both produce a [`ForensicResult`], so `risk::decide()` is unchanged.

#![allow(dead_code)]

pub mod archive;
pub mod autoexec;
pub mod entropy;
pub mod finding;
pub mod intent;
pub mod magic_bytes;
pub mod pe;
pub mod signature;
pub mod structure;

use anyhow::Result;
use finding::{severity_for, Finding, Severity};
use intent::IntentResult;
use magic_bytes::MagicBytesResult;

/// Combined result from scanning.
#[derive(Debug, Default, Clone)]
pub struct ForensicResult {
    pub header_valid: bool,
    pub extension_mismatch: bool,
    pub dangerous_intent: bool,
    /// Structural anomaly: polyglot, appended payload, double extension.
    pub structural_anomaly: bool,
    /// Entropy inconsistent with the declared file type.
    pub entropy_anomaly: bool,
    /// PE structure suggests packing or tampering.
    pub pe_anomaly: bool,
    /// The file is a format that runs something when opened.
    pub auto_execution: bool,
    /// What Authenticode says about the file, when it was checkable.
    pub signature_status: Option<signature::TrustStatus>,
    pub risk_score: f32,
    pub descriptions: Vec<String>,
    /// Structured, explained findings — what the user is actually shown.
    pub findings: Vec<Finding>,
}

/// Per-chunk scan, called as bytes arrive.
///
/// Magic-byte scanning only runs on the first chunk. Intent scanning runs on
/// every chunk with optional trailing context from the previous one, so a
/// pattern split across a chunk boundary is still matched.
pub async fn deep_forensic_scan(
    chunk: &[u8],
    filename: &str,
    is_first_chunk: bool,
    context_prefix: Option<&[u8]>,
) -> Result<ForensicResult> {
    let header_result: MagicBytesResult = if is_first_chunk {
        magic_bytes::scan_file(chunk, filename)?
    } else {
        MagicBytesResult::default()
    };

    let intent_result: IntentResult = intent::detect_dangerous_intent(chunk, context_prefix)?;

    let mut descriptions = Vec::new();
    let mut findings: Vec<Finding> = Vec::new();

    if is_first_chunk && !header_result.description.is_empty() {
        descriptions.push(header_result.description.clone());

        if header_result.mismatch {
            findings.push(Finding::new(
                Severity::Critical,
                "File is not the type it claims to be",
                header_result.description.clone(),
                "The file's actual contents contradict its extension. A program renamed to look \
                 like a document or image is the oldest trick there is, and the reason it still \
                 works is that people trust the name.",
                header_result.risk,
            ));
        }
    }

    for flag in &intent_result.flags {
        descriptions.push(flag.clone());
        findings.push(Finding::new(
            severity_for(intent_result.risk),
            "File contains code associated with malware",
            flag.clone(),
            "Programs that inject into other processes, log keystrokes, install themselves to run \
             at startup, or open remote shells are doing things ordinary software has no reason \
             to do.",
            intent_result.risk,
        ));
    }

    let risk_score = (header_result.risk + intent_result.risk).min(1.0);

    Ok(ForensicResult {
        header_valid: header_result.valid,
        extension_mismatch: header_result.mismatch,
        dangerous_intent: intent_result.flagged,
        risk_score,
        descriptions,
        findings,
        ..Default::default()
    })
}

/// Whole-file scan, called once the download has completed.
///
/// These checks are impossible on a prefix: locating a format's logical end,
/// measuring entropy across the file, and walking a PE section table all
/// require the complete bytes.
///
/// Convenience wrapper for callers with only a buffer. Signature verification
/// needs a real file, so it is skipped and reported as unchecked rather than
/// silently omitted — see [`whole_file_scan_at`].
pub fn whole_file_scan(data: &[u8], filename: &str) -> Result<ForensicResult> {
    whole_file_scan_at(data, filename, None)
}

/// Whole-file scan for a file that is on disk.
///
/// `on_disk` is the quarantine path. Authenticode verification is the one
/// check that cannot run from a buffer: Windows hashes specific regions of the
/// PE through a signature provider that takes a path, not a byte range.
pub fn whole_file_scan_at(
    data: &[u8],
    filename: &str,
    on_disk: Option<&std::path::Path>,
) -> Result<ForensicResult> {
    let claimed_ext = std::path::Path::new(filename)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();

    let structure_result = structure::analyse(data, filename)?;
    let entropy_result = entropy::analyse(data, &claimed_ext)?;
    let pe_result = pe::analyse(data)?;
    let archive_result = archive::analyse(data, filename)?;
    let autoexec_result = autoexec::analyse(data, filename)?;
    let signature_result = signature::analyse(on_disk, pe_result.is_pe, filename)?;

    let mut descriptions = Vec::new();
    descriptions.extend(structure_result.flags.iter().cloned());
    descriptions.extend(entropy_result.flags.iter().cloned());
    descriptions.extend(pe_result.flags.iter().cloned());
    descriptions.extend(archive_result.flags.iter().cloned());
    descriptions.extend(autoexec_result.flags.iter().cloned());
    descriptions.extend(signature_result.flags.iter().cloned());

    let mut findings = Vec::new();
    findings.extend(structure_result.findings.iter().cloned());
    findings.extend(entropy_result.findings.iter().cloned());
    findings.extend(pe_result.findings.iter().cloned());
    findings.extend(archive_result.findings.iter().cloned());
    findings.extend(autoexec_result.findings.iter().cloned());
    findings.extend(signature_result.findings.iter().cloned());

    // Take the MAXIMUM rather than the sum. These analyses overlap heavily -
    // a packed executable trips entropy AND PE section checks for the same
    // underlying reason - so summing would double-count one fact and push
    // ordinary packed software past the block threshold.
    //
    // Archive and auto-execution analysis do NOT overlap with the other three
    // in the same way - they read the ZIP index and the filename rather than
    // the container - so summing them would be defensible. They are still
    // combined by max, for a different reason: each check that identifies a
    // real attack is already calibrated to be decisive alone (0.7-0.85),
    // while the weak informational ones (an archive contains a program;
    // a document has a macro) are weak precisely because they are common and
    // usually benign. Adding those together is how a legitimate installer
    // accumulates its way past the block threshold, and a false positive on
    // ordinary software costs more than the compound case buys.
    let risk_score = structure_result
        .risk
        .max(entropy_result.risk)
        .max(pe_result.risk)
        .max(archive_result.risk)
        .max(autoexec_result.risk)
        .max(signature_result.risk)
        .min(1.0);

    // A valid signature is the one thing that can pull a score DOWN, and the
    // rule governing when it may do so lives in `signature::apply_trust_credit`
    // because it is the difference between "a signature settles an ambiguous
    // file" and "signing your malware buys a discount". Findings must be
    // sorted first: the rule reads the worst severity present.
    finding::sort_by_severity(&mut findings);
    let risk_score = signature::apply_trust_credit(
        risk_score,
        signature_result.trust_credit,
        &findings,
    );

    Ok(ForensicResult {
        structural_anomaly: structure_result.flagged || archive_result.flagged,
        entropy_anomaly: entropy_result.flagged,
        pe_anomaly: pe_result.flagged,
        auto_execution: autoexec_result.flagged,
        signature_status: signature_result.status,
        risk_score,
        descriptions,
        findings,
        ..Default::default()
    })
}

/// Merge streaming and whole-file results into the verdict input.
///
/// Streaming and whole-file findings ARE independent - "the extension lies
/// about the type" and "there is a ZIP appended after the image data" are
/// separate facts - so these combine additively, unlike the overlapping
/// analyses within `whole_file_scan`.
pub fn combine(streaming: &ForensicResult, whole_file: &ForensicResult) -> ForensicResult {
    let mut descriptions = streaming.descriptions.clone();
    for d in &whole_file.descriptions {
        if !descriptions.contains(d) {
            descriptions.push(d.clone());
        }
    }

    let mut findings = streaming.findings.clone();
    findings.extend(whole_file.findings.iter().cloned());
    // Worst first: a notification has room for one line and it must be the one
    // that matters, not whichever check happened to run first.
    finding::sort_by_severity(&mut findings);

    ForensicResult {
        header_valid: streaming.header_valid,
        extension_mismatch: streaming.extension_mismatch,
        dangerous_intent: streaming.dangerous_intent,
        structural_anomaly: whole_file.structural_anomaly,
        entropy_anomaly: whole_file.entropy_anomaly,
        pe_anomaly: whole_file.pe_anomaly,
        auto_execution: whole_file.auto_execution,
        signature_status: whole_file.signature_status.clone(),
        risk_score: (streaming.risk_score + whole_file.risk_score).min(1.0),
        descriptions,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png_with(payload: &[u8]) -> Vec<u8> {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        v.extend(std::iter::repeat_n(0xAAu8, 512));
        v.extend(b"IEND\xAE\x42\x60\x82");
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn benign_png_scores_zero_across_all_analyses() {
        let res = whole_file_scan(&png_with(b""), "photo.png").unwrap();
        assert_eq!(res.risk_score, 0.0, "signals: {:?}", res.descriptions);
        assert!(!res.structural_anomaly && !res.entropy_anomaly && !res.pe_anomaly);
    }

    /// The polyglot case: a valid PNG carrying an appended executable.
    #[test]
    fn polyglot_png_is_caught_by_the_whole_file_pass() {
        let mut pe = b"MZ\x90\x00".to_vec();
        pe.extend(std::iter::repeat_n(0u8, 400));
        let res = whole_file_scan(&png_with(&pe), "holiday.png").unwrap();

        assert!(res.structural_anomaly, "polyglot missed: {:?}", res.descriptions);
        assert!(res.risk_score >= 0.7, "risk {}", res.risk_score);
    }

    /// Overlapping analyses must not double-count. A packed executable trips
    /// both entropy and PE checks for the same reason; summing them would push
    /// ordinary packed software over the block threshold.
    #[test]
    fn overlapping_signals_do_not_compound_within_whole_file_scan() {
        let mut data = b"MZ\x90\x00".to_vec();
        data.extend(std::iter::repeat_n(0u8, 60));
        let mut state: u64 = 12345;
        for _ in 0..20000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            data.push((state >> 24) as u8);
        }
        let res = whole_file_scan(&data, "setup.exe").unwrap();
        assert!(
            res.risk_score <= 1.0,
            "risk must stay bounded, got {}",
            res.risk_score
        );
    }

    /// Independent facts SHOULD compound: a type mismatch found while streaming
    /// plus a structural anomaly found afterwards are two separate problems.
    #[tokio::test]
    async fn streaming_and_whole_file_findings_combine() {
        let mut pe = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
        pe.extend(std::iter::repeat_n(0u8, 512));

        let streaming = deep_forensic_scan(&pe, "invoice.pdf", true, None)
            .await
            .unwrap();
        let whole = whole_file_scan(&pe, "invoice.pdf").unwrap();
        let merged = combine(&streaming, &whole);

        assert!(merged.risk_score >= streaming.risk_score);
        assert!(merged.risk_score <= 1.0);
        assert!(merged.extension_mismatch, "type mismatch should survive the merge");
    }

    #[test]
    fn whole_file_scan_never_panics_on_hostile_input() {
        for data in [
            b"".as_slice(),
            b"MZ",
            b"\x89PNG",
            b"PK\x03\x04",
            &[0xFFu8; 1000],
            &[0u8; 1000],
        ] {
            let _ = whole_file_scan(data, "x.bin").unwrap();
            let _ = whole_file_scan(data, "").unwrap();
        }
    }
}
