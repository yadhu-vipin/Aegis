//! Structural analysis — what's hiding *inside* or *after* a well-formed file.
//!
//! Magic-byte checking asks "does the header match the extension?". That misses
//! the whole class of files where the header is entirely honest and the payload
//! rides along somewhere the format says nothing about:
//!
//!   * **Trailing data** — a PNG ends at its `IEND` chunk, a ZIP at its
//!     end-of-central-directory record. Bytes after that are invisible to the
//!     format but present on disk. Appending a ZIP to a PNG is the classic
//!     trick: image viewers render it, archive tools extract it, and the header
//!     never lies.
//!   * **Polyglots** — a file valid as two formats at once. Almost never
//!     accidental.
//!   * **Embedded executables** — a PE or ELF header inside what claims to be
//!     an image.
//!
//! Runs on the whole file once the download completes, not per-chunk: the
//! logical end of a format can only be located with the whole thing.

use anyhow::Result;

/// Result of structural analysis.
#[derive(Debug, Default, Clone)]
pub struct StructureResult {
    pub flagged: bool,
    pub flags: Vec<String>,
    pub risk: f32,
    /// Bytes present after the format's logical end, if any.
    pub trailing_bytes: usize,
}

/// Where a container format logically ends, if we can determine it.
///
/// `None` means "we do not know", which is different from "there is no trailing
/// data" — we only report trailing data when we are confident where the end is.
fn logical_end(data: &[u8]) -> Option<(usize, &'static str)> {
    // PNG: IHDR ... IEND + 4-byte CRC. Everything after is not part of the image.
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return find_subsequence(data, b"IEND").map(|i| (i + 8, "PNG"));
    }

    // GIF: terminated by 0x3B trailer.
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return data.iter().rposition(|&b| b == 0x3B).map(|i| (i + 1, "GIF"));
    }

    // JPEG: End Of Image marker FF D9.
    if data.starts_with(b"\xFF\xD8\xFF") {
        return find_last_subsequence(data, b"\xFF\xD9").map(|i| (i + 2, "JPEG"));
    }

    // ZIP (and the OOXML/JAR/APK family): End Of Central Directory record,
    // whose comment length field gives the true end.
    if data.starts_with(b"PK\x03\x04") {
        if let Some(eocd) = find_last_subsequence(data, b"PK\x05\x06") {
            // EOCD is 22 bytes; the last 2 are the comment length.
            if eocd + 22 <= data.len() {
                let comment_len =
                    u16::from_le_bytes([data[eocd + 20], data[eocd + 21]]) as usize;
                return Some((eocd + 22 + comment_len, "ZIP"));
            }
        }
    }

    // PDF: last %%EOF marker.
    if data.starts_with(b"%PDF") {
        return find_last_subsequence(data, b"%%EOF").map(|i| (i + 5, "PDF"));
    }

    None
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn find_last_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

/// Signatures worth finding *inside* a file that claims to be something else.
static EMBEDDED_SIGNATURES: &[(&[u8], &str, f32)] = &[
    (b"MZ\x90\x00", "Windows executable (PE)", 0.75),
    (b"\x7FELF", "Linux executable (ELF)", 0.7),
    (b"PK\x03\x04", "ZIP archive", 0.45),
    (b"Rar!\x1A\x07", "RAR archive", 0.5),
    (b"7z\xBC\xAF\x27\x1C", "7-Zip archive", 0.5),
    (b"\xCA\xFE\xBA\xBE", "Java class file", 0.55),
    (b"#!/bin/sh", "shell script", 0.5),
    (b"#!/bin/bash", "shell script", 0.5),
    (b"<?php", "PHP source", 0.6),
    (b"<script", "embedded script tag", 0.4),
];

/// True for formats where finding another format's header inside is suspicious.
///
/// Deliberately excludes containers that legitimately hold arbitrary data —
/// a ZIP is *supposed* to contain executables, and flagging that would fire on
/// every legitimate installer.
fn is_opaque_media(data: &[u8]) -> bool {
    data.starts_with(b"\x89PNG\r\n\x1a\n")
        || data.starts_with(b"\xFF\xD8\xFF")
        || data.starts_with(b"GIF87a")
        || data.starts_with(b"GIF89a")
        || data.starts_with(b"BM") // BMP
        || data.starts_with(b"RIFF") // WAV/AVI/WEBP
}

/// Analyse a complete file for structural anomalies.
pub fn analyse(data: &[u8], filename: &str) -> Result<StructureResult> {
    let mut flags = Vec::new();
    let mut risk: f32 = 0.0;
    let mut trailing_bytes = 0usize;

    // --- 1. Data after the format's logical end ---------------------------
    if let Some((end, format)) = logical_end(data) {
        if end < data.len() {
            trailing_bytes = data.len() - end;

            // A few stray bytes are usually padding or alignment. A meaningful
            // payload is not.
            if trailing_bytes >= 64 {
                let tail = &data[end..];
                let mut described = false;

                // Name what was appended when we can — far more actionable
                // than "there is extra data".
                for (sig, name, sig_risk) in EMBEDDED_SIGNATURES {
                    if tail.len() >= sig.len() && tail.starts_with(sig) {
                        flags.push(format!(
                            "[risk={:.2}] {format} file has {name} appended after its logical end \
                             ({trailing_bytes} bytes) - classic polyglot payload",
                            sig_risk.max(0.7)
                        ));
                        risk = risk.max(sig_risk.max(0.7));
                        described = true;
                        break;
                    }
                }

                if !described {
                    let r = 0.4;
                    flags.push(format!(
                        "[risk={r:.2}] {trailing_bytes} bytes present after the {format} \
                         file's logical end - hidden payload or steganographic container"
                    ));
                    risk = risk.max(r);
                }
            }
        }
    }

    // --- 2. Executables embedded inside opaque media ----------------------
    if is_opaque_media(data) {
        for (sig, name, sig_risk) in EMBEDDED_SIGNATURES {
            // Skip the file's own header.
            let search_from = std::cmp::min(16, data.len());
            if let Some(pos) = find_subsequence(&data[search_from..], sig) {
                let abs = pos + search_from;
                // Already reported as trailing data? Don't double-count.
                if let Some((end, _)) = logical_end(data) {
                    if abs >= end {
                        continue;
                    }
                }
                flags.push(format!(
                    "[risk={sig_risk:.2}] {name} signature found at offset {abs} inside an \
                     image/media file - content does not match the container"
                ));
                risk = risk.max(*sig_risk);
            }
        }
    }

    // --- 3. Double extension -----------------------------------------------
    // "invoice.pdf.exe" relies on the user reading only the first extension.
    if let Some(flag) = check_double_extension(filename) {
        flags.push(flag);
        risk = risk.max(0.65);
    }

    let risk = risk.min(1.0);
    Ok(StructureResult {
        flagged: !flags.is_empty(),
        flags,
        risk,
        trailing_bytes,
    })
}

/// Detect a document-looking extension followed by an executable one.
fn check_double_extension(filename: &str) -> Option<String> {
    const EXECUTABLE: &[&str] = &[
        "exe", "scr", "com", "bat", "cmd", "pif", "vbs", "vbe", "js", "jse", "wsf", "wsh",
        "msi", "jar", "ps1", "hta", "cpl", "lnk",
    ];
    const DOCUMENT: &[&str] = &[
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg",
        "png", "gif", "mp3", "mp4", "avi", "zip", "csv",
    ];

    let parts: Vec<&str> = filename.split('.').collect();
    if parts.len() < 3 {
        return None;
    }

    let last = parts.last()?.to_lowercase();
    let second_last = parts[parts.len() - 2].to_lowercase();

    if EXECUTABLE.contains(&last.as_str()) && DOCUMENT.contains(&second_last.as_str()) {
        return Some(format!(
            "[risk=0.65] Double extension: file appears to be .{second_last} but is actually \
             .{last} - relies on the user reading only the first extension"
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(payload_after: &[u8]) -> Vec<u8> {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        v.extend(std::iter::repeat_n(0xAAu8, 512)); // image data
        v.extend(b"IEND\xAE\x42\x60\x82"); // IEND + CRC
        v.extend_from_slice(payload_after);
        v
    }

    #[test]
    fn clean_png_is_not_flagged() {
        let res = analyse(&png(b""), "photo.png").unwrap();
        assert!(!res.flagged, "clean PNG flagged: {:?}", res.flags);
        assert_eq!(res.trailing_bytes, 0);
    }

    /// The classic polyglot: a valid PNG with a ZIP appended. Image viewers
    /// render it, archive tools extract it, and the magic bytes never lie.
    #[test]
    fn png_with_appended_zip_is_flagged() {
        let mut zip = b"PK\x03\x04".to_vec();
        zip.extend(std::iter::repeat_n(0x11u8, 200));
        let res = analyse(&png(&zip), "photo.png").unwrap();

        assert!(res.flagged, "appended ZIP not detected");
        assert!(res.risk >= 0.7, "risk too low: {}", res.risk);
        assert!(res.trailing_bytes > 0);
        assert!(
            res.flags.iter().any(|f| f.contains("ZIP") && f.contains("appended")),
            "flag should name the appended format: {:?}",
            res.flags
        );
    }

    #[test]
    fn png_with_appended_executable_is_high_risk() {
        let mut pe = b"MZ\x90\x00".to_vec();
        pe.extend(std::iter::repeat_n(0u8, 300));
        let res = analyse(&png(&pe), "holiday.png").unwrap();
        assert!(res.risk >= 0.7, "appended PE should be high risk: {}", res.risk);
    }

    /// A handful of padding bytes is normal and must not fire.
    #[test]
    fn small_trailing_padding_is_tolerated() {
        let res = analyse(&png(&[0u8; 8]), "photo.png").unwrap();
        assert!(!res.flagged, "8 padding bytes flagged: {:?}", res.flags);
    }

    #[test]
    fn executable_embedded_in_jpeg_is_flagged() {
        let mut v = b"\xFF\xD8\xFF\xE0".to_vec();
        v.extend(std::iter::repeat_n(0x22u8, 100));
        v.extend(b"MZ\x90\x00");
        v.extend(std::iter::repeat_n(0u8, 100));
        v.extend(b"\xFF\xD9");
        let res = analyse(&v, "picture.jpg").unwrap();
        assert!(res.flagged, "embedded PE inside JPEG missed");
        assert!(res.risk >= 0.7);
    }

    /// A ZIP legitimately contains executables. Flagging that would fire on
    /// every installer and destroy the signal-to-noise ratio.
    #[test]
    fn executable_inside_zip_is_not_flagged() {
        let mut v = b"PK\x03\x04".to_vec();
        v.extend(std::iter::repeat_n(0u8, 50));
        v.extend(b"MZ\x90\x00");
        v.extend(std::iter::repeat_n(0u8, 50));
        v.extend(b"PK\x05\x06");
        v.extend(std::iter::repeat_n(0u8, 20));
        let res = analyse(&v, "installer.zip").unwrap();
        assert!(
            !res.flagged,
            "an executable inside a ZIP is normal and must not flag: {:?}",
            res.flags
        );
    }

    #[test]
    fn double_extension_is_flagged() {
        for name in ["invoice.pdf.exe", "photo.jpg.scr", "report.docx.vbs", "song.mp3.bat"] {
            let res = analyse(b"\x89PNG\r\n\x1a\n", name).unwrap();
            assert!(res.flagged, "double extension {name:?} not flagged");
            assert!(res.risk >= 0.65);
        }
    }

    #[test]
    fn ordinary_names_are_not_double_extensions() {
        for name in ["archive.tar.gz", "notes.v2.pdf", "photo.png", "my.file.name.txt"] {
            let res = analyse(b"\x89PNG\r\n\x1a\n", name).unwrap();
            assert!(
                !res.flags.iter().any(|f| f.contains("Double extension")),
                "{name:?} wrongly flagged as a double extension"
            );
        }
    }

    /// Must never panic on hostile input — truncated headers, empty files,
    /// and files consisting only of a magic number.
    #[test]
    fn malformed_input_does_not_panic() {
        for data in [
            b"".as_slice(),
            b"\x89",
            b"\x89PNG",
            b"\x89PNG\r\n\x1a\n",
            b"PK\x03\x04",
            b"PK\x05\x06",
            b"%PDF",
            b"\xFF\xD8\xFF",
        ] {
            let _ = analyse(data, "x.bin").unwrap();
        }
    }
}
