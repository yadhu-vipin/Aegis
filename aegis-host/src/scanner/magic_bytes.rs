//! Magic-byte scanner — verifies file content matches its claimed extension.
//!
//! Operates on the FIRST chunk of a download only (is_first_chunk=true).
//! Returns a `MagicBytesResult` used by the orchestrator to compute risk score.

use anyhow::Result;
use std::path::Path;

/// Result from magic-byte scanning.
#[derive(Debug, Default, Clone)]
pub struct MagicBytesResult {
    /// True if we could identify the file type from its magic bytes.
    pub valid: bool,
    /// True if detected type does NOT match claimed extension.
    pub mismatch: bool,
    /// Risk contribution from this scan (0.0 = clean, 1.0 = critical mismatch).
    pub risk: f32,
    /// Human-readable description of the finding.
    pub description: String,
}

/// Known file signatures mapped to canonical type names.
struct Signature {
    bytes: &'static [u8],
    type_name: &'static str,
}

/// All signatures we check. Order matters — more specific patterns first.
static SIGNATURES: &[Signature] = &[
    // Windows PE executables
    Signature { bytes: b"\x4D\x5A", type_name: "exe" },
    // ELF binaries (Linux/Unix/Android)
    Signature { bytes: b"\x7F\x45\x4C\x46", type_name: "elf" },
    // Java class files
    Signature { bytes: b"\xCA\xFE\xBA\xBE", type_name: "class" },
    // Script shebangs (#!)
    Signature { bytes: b"\x23\x21", type_name: "script" },
    // PDF
    Signature { bytes: b"\x25\x50\x44\x46", type_name: "pdf" },
    // ZIP / Office (OOXML) / JAR
    Signature { bytes: b"\x50\x4B\x03\x04", type_name: "zip" },
    // JPEG
    Signature { bytes: b"\xFF\xD8\xFF", type_name: "jpg" },
    // PNG
    Signature { bytes: b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", type_name: "png" },
    // GIF87a / GIF89a
    Signature { bytes: b"GIF87a", type_name: "gif" },
    Signature { bytes: b"GIF89a", type_name: "gif" },
    // RAR
    Signature { bytes: b"\x52\x61\x72\x21\x1A\x07", type_name: "rar" },
    // 7-Zip
    Signature { bytes: b"\x37\x7A\xBC\xAF\x27\x1C", type_name: "7z" },
    // Gzip
    Signature { bytes: b"\x1F\x8B", type_name: "gz" },
    // BZip2
    Signature { bytes: b"\x42\x5A\x68", type_name: "bz2" },
    // XZ
    Signature { bytes: b"\xFD\x37\x7A\x58\x5A\x00", type_name: "xz" },
    // Mach-O (macOS binaries)
    Signature { bytes: b"\xFE\xED\xFA\xCE", type_name: "macho" },
    Signature { bytes: b"\xFE\xED\xFA\xCF", type_name: "macho" },
    Signature { bytes: b"\xCE\xFA\xED\xFE", type_name: "macho" },
    Signature { bytes: b"\xCF\xFA\xED\xFE", type_name: "macho" },
];

/// Extension groups: maps detected type -> set of valid claimed extensions.
/// Any extension in the set is acceptable for that detected type.
fn valid_extensions_for_type(detected: &str) -> &'static [&'static str] {
    match detected {
        "exe" => &["exe", "dll", "sys", "scr", "com"],
        "elf" => &["elf", "so", "bin", "out"],
        "class" => &["class", "jar"],
        "script" => &["sh", "bash", "py", "pl", "rb", "zsh", "fish"],
        "pdf" => &["pdf"],
        // ZIP is legitimately inside many office formats
        "zip" => &["zip", "docx", "xlsx", "pptx", "odt", "ods", "odp", "jar", "apk", "xpi"],
        "jpg" => &["jpg", "jpeg"],
        "png" => &["png"],
        "gif" => &["gif"],
        "rar" => &["rar", "cbr"],
        "7z" => &["7z"],
        "gz" => &["gz", "tgz"],
        "bz2" => &["bz2"],
        "xz" => &["xz"],
        "macho" => &["dylib", "bin", "app"],
        _ => &[],
    }
}

/// Extension groups that are especially dangerous to mismatch
/// (executable masquerading as something benign).
fn is_executable_type(detected: &str) -> bool {
    matches!(detected, "exe" | "elf" | "class" | "script" | "macho")
}

/// Scan the first chunk of a download for magic byte / extension mismatches.
pub fn scan_file(data: &[u8], filename: &str) -> Result<MagicBytesResult> {
    if data.len() < 2 {
        return Ok(MagicBytesResult {
            valid: false,
            mismatch: false,
            risk: 0.05,
            description: "Chunk too small for magic-byte identification".to_string(),
        });
    }

    let detected_type = detect_type(data);
    let claimed_ext = get_extension(filename);

    tracing::debug!(
        filename = %filename,
        detected = detected_type.unwrap_or("unknown"),
        claimed = %claimed_ext,
        "Magic byte scan"
    );

    match detected_type {
        None => {
            // Unknown type — not necessarily suspicious, just unidentified
            Ok(MagicBytesResult {
                valid: false,
                mismatch: false,
                risk: 0.05,
                description: format!(
                    "Unknown file type for '{}' (no matching magic bytes)",
                    filename
                ),
            })
        }
        Some(dtype) => {
            let valid_exts = valid_extensions_for_type(dtype);
            let ext_ok = valid_exts.contains(&claimed_ext.as_str());

            if ext_ok {
                Ok(MagicBytesResult {
                    valid: true,
                    mismatch: false,
                    risk: 0.0,
                    description: format!(
                        "File identity verified: detected '{}', claimed '.{}'",
                        dtype, claimed_ext
                    ),
                })
            } else {
                // Mismatch — how bad depends on whether it's an executable hiding
                let (risk, severity) = if is_executable_type(dtype) {
                    (0.8, "CRITICAL")
                } else {
                    (0.4, "WARNING")
                };
                Ok(MagicBytesResult {
                    valid: true,
                    mismatch: true,
                    risk,
                    description: format!(
                        "[{}] File type mismatch: detected '{}' but claimed extension is '.{}' — possible trojan/polyglot",
                        severity, dtype, claimed_ext
                    ),
                })
            }
        }
    }
}

/// Detect file type from magic bytes. Returns `None` for unknown types.
fn detect_type(data: &[u8]) -> Option<&'static str> {
    for sig in SIGNATURES {
        if data.starts_with(sig.bytes) {
            return Some(sig.type_name);
        }
    }
    None
}

/// Extract and normalize the file extension from a filename.
fn get_extension(filename: &str) -> String {
    Path::new(filename)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exe_disguised_as_jpg() {
        let fake_jpg_header = b"\x4D\x5A\x90\x00\x03\x00\x00\x00"; // PE header (exe)
        let res = scan_file(fake_jpg_header, "photo.jpg").unwrap();
        assert!(res.mismatch);
        assert_eq!(res.risk, 0.8);
    }

    #[test]
    fn test_valid_png() {
        let png_header = b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A";
        let res = scan_file(png_header, "image.png").unwrap();
        assert!(!res.mismatch);
        assert_eq!(res.risk, 0.0);
    }

    #[test]
    fn test_valid_docx_as_zip() {
        let zip_header = b"\x50\x4B\x03\x04\x14\x00\x06\x00";
        let res = scan_file(zip_header, "document.docx").unwrap();
        assert!(!res.mismatch);
        assert_eq!(res.risk, 0.0);
    }
}
