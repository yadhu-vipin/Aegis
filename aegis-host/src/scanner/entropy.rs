//! Shannon entropy analysis — finding packed, encrypted, or hidden payloads.
//!
//! Entropy measures how unpredictable bytes are, in bits per byte (0.0–8.0).
//! It is a *shape* signal, not a signature, so it catches things no pattern
//! list can: a packed dropper whose strings are all encrypted, a payload
//! concealed in the tail of an image, ransomware carrying an encrypted blob.
//!
//! Typical values:
//!
//! | Content                          | Entropy   |
//! |----------------------------------|-----------|
//! | English text, source code        | 4.0 - 5.0 |
//! | Ordinary PE executable           | 5.5 - 6.5 |
//! | **Packed / obfuscated PE**       | **7.0+**  |
//! | Compressed (ZIP/JPEG/PNG)        | 7.9 - 8.0 |
//! | Encrypted / random               | ~8.0      |
//!
//! The interpretation depends entirely on what the file claims to be. 7.99 in a
//! ZIP is exactly right; 7.99 in a `.txt` means it is not text. That context
//! dependence is why this reports alongside the declared type rather than
//! thresholding blindly — used naively, entropy is a false-positive machine.

use anyhow::Result;

/// Window size for the sliding scan. Small enough to localise a payload inside
/// a larger benign file, large enough that the estimate is statistically
/// meaningful (256 possible byte values need a reasonable sample).
pub const WINDOW_SIZE: usize = 4096;

use crate::scanner::finding::{Finding, Severity};

#[derive(Debug, Default, Clone)]
pub struct EntropyResult {
    pub flagged: bool,
    pub flags: Vec<String>,
    pub findings: Vec<Finding>,
    pub risk: f32,
    /// Entropy across the whole input.
    pub overall: f32,
    /// Highest entropy seen in any single window.
    pub max_window: f32,
    /// Byte offset of that window.
    pub max_window_offset: usize,
}

/// Shannon entropy of a byte slice, in bits per byte.
///
/// H = -sum(p_i * log2(p_i)) over the 256 possible byte values.
pub fn shannon(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f32;
    let mut h = 0.0f32;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f32 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Formats whose content is inherently compressed, so high entropy is expected
/// and carries no signal.
fn is_expected_high_entropy(data: &[u8], claimed_ext: &str) -> bool {
    const COMPRESSED_EXT: &[&str] = &[
        "zip", "gz", "tgz", "bz2", "xz", "7z", "rar", "jpg", "jpeg", "png", "gif", "webp",
        "mp3", "mp4", "avi", "mkv", "mov", "docx", "xlsx", "pptx", "jar", "apk", "pdf",
        "woff", "woff2",
    ];
    if COMPRESSED_EXT.contains(&claimed_ext) {
        return true;
    }
    // Trust content over the name.
    data.starts_with(b"PK\x03\x04")
        || data.starts_with(b"\x1F\x8B")
        || data.starts_with(b"\xFF\xD8\xFF")
        || data.starts_with(b"\x89PNG")
        || data.starts_with(b"Rar!")
        || data.starts_with(b"7z\xBC\xAF\x27\x1C")
        || data.starts_with(b"%PDF")
}

/// Formats that should be mostly plain text. High entropy here is a strong
/// signal — it means the file is not what it says it is.
fn should_be_text(claimed_ext: &str) -> bool {
    const TEXT_EXT: &[&str] = &[
        "txt", "csv", "log", "md", "json", "xml", "html", "htm", "css", "js", "ts", "py",
        "rs", "c", "h", "cpp", "java", "sh", "bat", "ps1", "yml", "yaml", "ini", "cfg",
    ];
    TEXT_EXT.contains(&claimed_ext)
}

/// Analyse entropy across a complete file.
pub fn analyse(data: &[u8], claimed_ext: &str) -> Result<EntropyResult> {
    let mut result = EntropyResult {
        overall: shannon(data),
        ..Default::default()
    };

    // Sliding windows, stepped at half-width so a payload straddling a boundary
    // is still centred in some window.
    let step = WINDOW_SIZE / 2;
    let mut offset = 0usize;
    while offset < data.len() {
        let end = std::cmp::min(offset + WINDOW_SIZE, data.len());
        // Ignore short tails — too small for a meaningful estimate.
        if end - offset >= WINDOW_SIZE / 4 {
            let h = shannon(&data[offset..end]);
            if h > result.max_window {
                result.max_window = h;
                result.max_window_offset = offset;
            }
        }
        if end == data.len() {
            break;
        }
        offset += step;
    }

    let ext = claimed_ext.to_lowercase();
    let mut risk: f32 = 0.0;

    if should_be_text(&ext) {
        // A text file has no business being high-entropy.
        if result.overall > 6.5 {
            let r = 0.7;
            result.findings.push(Finding::new(
                Severity::High,
                "File contents are not readable text",
                format!(
                    "Randomness measured at {:.2} bits per byte. Ordinary text measures 4.0-5.0; \
                     anything above 6.5 is not text at all.",
                    result.overall
                ),
                format!(
                    "This is named .{ext}, which should be plain readable text, but its contents \
                     are encrypted, compressed or executable. Something is deliberately \
                     misrepresenting what this file is."
                ),
                r,
            ));
            risk = risk.max(r);
        } else if result.overall > 5.5 {
            let r = 0.35;
            result.findings.push(Finding::new(
                Severity::Medium,
                "File is less readable than a text file should be",
                format!(
                    "Randomness measured at {:.2} bits per byte, above the 4.0-5.0 typical of text.",
                    result.overall
                ),
                format!("A .{ext} file with this much randomness may contain encoded or binary data rather than text."),
                r,
            ));
            risk = risk.max(r);
        }
    } else if !is_expected_high_entropy(data, &ext) {
        // Executables and unknown types: high entropy suggests packing.
        if result.overall > 7.2 {
            let r = 0.5;
            result.findings.push(Finding::new(
                Severity::Medium,
                "Program contents are hidden (packed or encrypted)",
                format!(
                    "Randomness measured at {:.2} bits per byte across the whole file. An ordinary \
                     program measures 5.5-6.5; above 7.2 means the contents are compressed or \
                     encrypted.",
                    result.overall
                ),
                "Packing hides what a program actually does until it runs, which is why malware \
                 uses it to defeat scanners. Some legitimate software is packed too, so this is a \
                 warning sign rather than proof.",
                r,
            ));
            risk = risk.max(r);
        }

        // A localised high-entropy region inside otherwise ordinary content is
        // the shape of an embedded encrypted payload — more specific than a
        // high whole-file average.
        //
        // NOT applied to executables. A normal PE is full of high-entropy
        // pockets by design: compressed resources in `.rsrc`, embedded PNG and
        // ICO icons, and the Authenticode certificate blob appended after the
        // last section. `notepad.exe` trips this at offset 180224 with a window
        // measuring 7.96 against a whole-file 6.48 — the check is describing
        // Windows' own resource compression and calling it a hidden payload.
        //
        // A signal that fires on essentially every signed Windows binary
        // carries no information about the one being scanned. The whole-file
        // threshold above still applies to executables, and that one is
        // meaningful: a fully packed binary is uniformly high-entropy, which is
        // a different shape entirely.
        let is_executable = data.starts_with(b"MZ") || data.starts_with(b"\x7FELF");
        if !is_executable
            && result.max_window > 7.5
            && result.overall < 6.5
            && data.len() > WINDOW_SIZE * 2
        {
            let r = 0.45;
            result.findings.push(Finding::new(
                Severity::Medium,
                "Encrypted block hidden inside ordinary content",
                format!(
                    "A region at byte offset {} measures {:.2} bits per byte, while the file \
                     overall measures only {:.2}.",
                    result.max_window_offset, result.max_window, result.overall
                ),
                "A concentrated pocket of encrypted data inside otherwise normal content is the \
                 shape of a hidden payload — a carrier file with something concealed in it, \
                 decrypted only when it runs.",
                r,
            ));
            risk = risk.max(r);
        }
    }

    result.risk = risk.min(1.0);
    result.flags = result.findings.iter().map(|f| f.one_line()).collect();
    result.flagged = !result.findings.is_empty();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random bytes — a stand-in for encrypted content.
    fn pseudo_random(n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        let mut state: u64 = 0x2545F491_4F6CDD1D;
        for _ in 0..n {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            v.push((state >> 24) as u8);
        }
        v
    }

    #[test]
    fn entropy_bounds_are_sane() {
        assert_eq!(shannon(&[]), 0.0);
        // A single repeated byte is perfectly predictable.
        assert!(shannon(&[0x41; 4096]) < 0.01);
        // All 256 values equally often is maximal.
        let uniform: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!(shannon(&uniform) > 7.9, "got {}", shannon(&uniform));
    }

    #[test]
    fn english_text_lands_in_the_expected_band() {
        let text = "The quick brown fox jumps over the lazy dog. ".repeat(200);
        let h = shannon(text.as_bytes());
        assert!((3.0..5.5).contains(&h), "English text entropy was {h}");
    }

    /// A .txt full of encrypted bytes is not a text file.
    #[test]
    fn encrypted_content_in_a_text_file_is_flagged() {
        let data = pseudo_random(8192);
        let res = analyse(&data, "txt").unwrap();
        assert!(res.flagged, "high-entropy .txt not flagged");
        assert!(res.risk >= 0.7, "risk was {}", res.risk);
    }

    /// A ZIP is compressed by definition — flagging it would fire on every
    /// legitimate archive and drown out real signal.
    #[test]
    fn compressed_formats_are_not_flagged_for_high_entropy() {
        let mut data = b"PK\x03\x04".to_vec();
        data.extend(pseudo_random(8192));
        for ext in ["zip", "jpg", "png", "docx", "mp4"] {
            let res = analyse(&data, ext).unwrap();
            assert!(
                !res.flagged,
                ".{ext} flagged for expected high entropy: {:?}",
                res.flags
            );
        }
    }

    #[test]
    fn plain_text_file_is_not_flagged() {
        let text = "function greet(name) { return `hello ${name}`; }\n".repeat(300);
        let res = analyse(text.as_bytes(), "js").unwrap();
        assert!(!res.flagged, "ordinary source flagged: {:?}", res.flags);
    }

    /// An encrypted blob hidden inside otherwise ordinary content — more
    /// specific than a high whole-file average, and the shape of a dropper
    /// carrying a payload.
    #[test]
    fn localised_high_entropy_region_is_detected() {
        // A legacy OLE document: not text, not a compressed container, and not
        // an executable — so the windowed check applies. This is also the
        // realistic shape of the thing being detected, an Office document with
        // an encrypted payload embedded in it.
        let mut data = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1".to_vec();
        data.extend(b"ordinary document text and strings ".repeat(500));
        data.extend(pseudo_random(6000));
        data.extend(b"more ordinary trailing content ".repeat(500));

        let res = analyse(&data, "doc").unwrap();
        assert!(
            res.max_window > 7.5,
            "embedded random region not found, max window {}",
            res.max_window
        );
        assert!(res.flagged, "localised high-entropy region not flagged");
    }

    /// Executables are exempt from the windowed check, and must be.
    ///
    /// A normal PE is full of high-entropy pockets: compressed resources,
    /// embedded PNG and ICO icons, and the Authenticode certificate appended
    /// after the last section. `notepad.exe` trips the raw measurement at 7.96
    /// against a whole-file 6.48 — so without this exemption the check reports
    /// Windows' own resource compression as a hidden encrypted payload, on
    /// essentially every signed binary in existence.
    #[test]
    fn executables_are_exempt_from_the_windowed_check() {
        let mut data = b"MZ\x90\x00".to_vec();
        data.extend(b"ordinary program text and strings ".repeat(500));
        data.extend(pseudo_random(6000)); // stands in for a compressed .rsrc
        data.extend(b"more ordinary trailing content ".repeat(500));

        let res = analyse(&data, "exe").unwrap();
        assert!(
            res.max_window > 7.5,
            "fixture should still contain a high-entropy window"
        );
        assert!(
            !res.findings.iter().any(|f| f.title.contains("Encrypted block")),
            "a PE with a compressed resource section was reported as carrying a \
             hidden encrypted payload: {:?}",
            res.flags
        );
    }

    /// The whole-file threshold still applies to executables, and should: a
    /// fully packed binary is uniformly high-entropy, which is a different
    /// shape from one high-entropy section.
    #[test]
    fn fully_packed_executable_is_still_flagged() {
        let mut data = b"MZ\x90\x00".to_vec();
        data.extend(pseudo_random(60_000));

        let res = analyse(&data, "exe").unwrap();
        assert!(
            res.flagged,
            "a uniformly high-entropy executable should still be flagged as packed"
        );
    }

    #[test]
    fn empty_and_tiny_inputs_do_not_panic() {
        for data in [b"".as_slice(), b"a", b"ab", &[0u8; 100]] {
            let _ = analyse(data, "txt").unwrap();
        }
    }

    #[test]
    fn window_offset_points_at_the_payload() {
        let mut data = vec![b'A'; 8192];
        data.extend(pseudo_random(8192));
        let res = analyse(&data, "bin").unwrap();
        assert!(
            res.max_window_offset >= 4096,
            "max-entropy window at {} should be in the second half",
            res.max_window_offset
        );
    }
}
